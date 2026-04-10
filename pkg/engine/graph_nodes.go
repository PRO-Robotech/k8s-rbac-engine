package engine

import (
	"fmt"
	"sort"
	"strings"

	rbacv1 "k8s.io/api/rbac/v1"

	api "k8s-rbac-engine/pkg/apis/rbacgraph"
	"k8s-rbac-engine/pkg/indexer"
)

const (
	nodeIDPrefixRole      = "role:"
	nodeIDPrefixBinding   = "binding:"
	nodeIDPrefixSubject   = "subject:"
	nodeIDPrefixPod       = "pod:"
	nodeIDPrefixWorkload  = "workload:"
	nodeIDPrefixOverflow  = "overflow:"
	edgeIDPrefix          = "edge:"
	edgeExplainAggregates = "ClusterRole contributes rules via aggregationRule"
	edgeExplainGrants     = "Role referenced by binding"
	edgeExplainSubjects   = "Binding targets subject"
	edgeExplainRunsAs     = "ServiceAccount used by pod"
	edgeExplainOwnedBy    = "Owner reference chain"
)

func roleNodeID(role *indexer.RoleRecord) string {
	if role.Namespace == "" {
		return fmt.Sprintf("%s%s:%s", nodeIDPrefixRole, strings.ToLower(role.Kind), role.Name)
	}

	return fmt.Sprintf("%s%s:%s/%s", nodeIDPrefixRole, strings.ToLower(role.Kind), role.Namespace, role.Name)
}

func bindingNodeID(binding *indexer.BindingRecord) string {
	if binding.Namespace == "" {
		return fmt.Sprintf("%s%s:%s", nodeIDPrefixBinding, strings.ToLower(binding.Kind), binding.Name)
	}

	return fmt.Sprintf("%s%s:%s/%s", nodeIDPrefixBinding, strings.ToLower(binding.Kind), binding.Namespace, binding.Name)
}

func subjectNodeID(subject rbacv1.Subject) string {
	typ := subjectType(subject.Kind)
	kind := strings.ToLower(string(typ))
	if typ == api.GraphNodeTypeServiceAccount && subject.Namespace != "" {
		return fmt.Sprintf("%s%s:%s/%s", nodeIDPrefixSubject, kind, subject.Namespace, subject.Name)
	}

	return fmt.Sprintf("%s%s:%s", nodeIDPrefixSubject, kind, subject.Name)
}

func podNodeID(pod *indexer.PodRecord) string {
	return nodeIDPrefixPod + pod.Namespace + "/" + pod.Name
}

func workloadNodeID(workload *indexer.WorkloadRecord) string {
	kind := strings.ToLower(workload.Kind)

	return nodeIDPrefixWorkload + kind + ":" + workload.Namespace + "/" + workload.Name
}

func podOverflowNodeID(subjectNodeID string) string {
	return nodeIDPrefixOverflow + "pod:" + subjectNodeID
}

func workloadOverflowNodeID(podNodeID string) string {
	return nodeIDPrefixOverflow + "workload:" + podNodeID
}

func edgeIDFor(from, to string, edgeType api.GraphEdgeType) string {
	return edgeIDPrefix + from + "->" + to + ":" + string(edgeType)
}

func roleType(role *indexer.RoleRecord) api.GraphNodeType {
	if role.Kind == indexer.KindClusterRole {
		return api.GraphNodeTypeClusterRole
	}

	return api.GraphNodeTypeRole
}

func bindingType(binding *indexer.BindingRecord) api.GraphNodeType {
	if binding.Kind == indexer.KindClusterRoleBinding {
		return api.GraphNodeTypeClusterRoleBinding
	}

	return api.GraphNodeTypeRoleBinding
}

func subjectType(kind string) api.GraphNodeType {
	switch strings.ToLower(kind) {
	case strings.ToLower(indexer.SubjectKindGroup):
		return api.GraphNodeTypeGroup
	case strings.ToLower(indexer.SubjectKindServiceAccount):
		return api.GraphNodeTypeServiceAccount
	default:
		return api.GraphNodeTypeUser
	}
}

func (qc *queryContext) upsertRoleNode(role *indexer.RoleRecord, aggregationSources []indexer.RoleID, matchedRefs []api.RuleRef) string {
	roleID := roleNodeID(role)
	nodes := &qc.status.Graph.Nodes
	if _, exists := qc.nodeSeen[roleID]; !exists {
		node := api.GraphNode{
			ID:          roleID,
			Type:        roleType(role),
			Name:        role.Name,
			Namespace:   role.Namespace,
			Labels:      role.Labels,
			Annotations: role.Annotations,
			Assessment:  lookupAssessmentForRole(qc.reportLookup, role),
		}
		if len(aggregationSources) > 0 {
			node.Aggregated = true
			node.AggregationSources = make([]string, 0, len(aggregationSources))
			for _, sourceID := range aggregationSources {
				node.AggregationSources = append(node.AggregationSources, string(sourceID))
			}
		}
		if len(matchedRefs) > 0 {
			node.MatchedRuleRefs = append([]api.RuleRef(nil), matchedRefs...)
		}
		*nodes = append(*nodes, node)
		qc.nodeSeen[roleID] = struct{}{}
		qc.nodeIndex[roleID] = len(*nodes) - 1

		return roleID
	}

	idx, ok := qc.nodeIndex[roleID]
	if ok {
		if len(aggregationSources) > 0 {
			(*nodes)[idx].Aggregated = true
			incoming := make([]string, 0, len(aggregationSources))
			for _, sourceID := range aggregationSources {
				incoming = append(incoming, string(sourceID))
			}
			(*nodes)[idx].AggregationSources = mergeSortedUniqueStrings((*nodes)[idx].AggregationSources, incoming)
		}
		if len(matchedRefs) > 0 {
			(*nodes)[idx].MatchedRuleRefs = mergeRuleRefs((*nodes)[idx].MatchedRuleRefs, matchedRefs)
		}
	}

	return roleID
}

func (qc *queryContext) addNodeIfMissing(node api.GraphNode) bool {
	if _, exists := qc.nodeSeen[node.ID]; exists {
		return false
	}
	qc.status.Graph.Nodes = append(qc.status.Graph.Nodes, node)
	qc.nodeSeen[node.ID] = struct{}{}

	return true
}

func (qc *queryContext) appendEdgeIfMissing(edge api.GraphEdge) {
	if _, exists := qc.edgeSeen[edge.ID]; exists {
		return
	}
	qc.status.Graph.Edges = append(qc.status.Graph.Edges, edge)
	qc.edgeSeen[edge.ID] = struct{}{}
}

func appendUniqueString(values *[]string, seen map[string]struct{}, value string) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return
	}
	if _, exists := seen[trimmed]; exists {
		return
	}
	*values = append(*values, trimmed)
	seen[trimmed] = struct{}{}
}

func mergeSortedUniqueStrings(existing, incoming []string) []string {
	seen := make(map[string]struct{}, len(existing)+len(incoming))
	merged := make([]string, 0, len(existing)+len(incoming))
	for _, value := range existing {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		merged = append(merged, value)
	}
	for _, value := range incoming {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		merged = append(merged, value)
	}
	sort.Strings(merged)

	return merged
}

func mergeRuleRefs(existing, incoming []api.RuleRef) []api.RuleRef {
	seen := make(map[ruleRefDedupeKey]struct{}, len(existing)+len(incoming))
	merged := make([]api.RuleRef, 0, len(existing)+len(incoming))
	appendRef := func(ref api.RuleRef) {
		key := ruleRefDedupeKey{
			apiVersion:      ref.APIVersion,
			apiGroup:        ref.APIGroup,
			resource:        ref.Resource,
			subresource:     ref.Subresource,
			verb:            ref.Verb,
			resourceNames:   strings.Join(ref.ResourceNames, ","),
			nonResourceURLs: strings.Join(ref.NonResourceURLs, ","),
			sourceObjectUID: ref.SourceObjectUID,
			sourceRuleIndex: ref.SourceRuleIndex,
		}
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		merged = append(merged, ref)
	}

	for i := range existing {
		appendRef(existing[i])
	}
	for i := range incoming {
		appendRef(incoming[i])
	}

	return merged
}

type ruleRefDedupeKey struct {
	apiVersion      string
	apiGroup        string
	resource        string
	subresource     string
	verb            string
	resourceNames   string
	nonResourceURLs string
	sourceObjectUID string
	sourceRuleIndex int
}
