package engine

import (
	api "k8s-rbac-engine/pkg/apis/rbacgraph"
	"k8s-rbac-engine/pkg/indexer"
	"k8s-rbac-engine/pkg/matcher"
)

// QuerySubjectsBySelectorGraph returns the subject-rooted graph for a selector match.
func (e *Engine) QuerySubjectsBySelectorGraph(
	snapshot *indexer.Snapshot,
	spec api.SubjectsBySelectorGraphSpec,
	_ *indexer.APIDiscoveryCache,
) api.SubjectsBySelectorGraphStatus {
	normalized := spec
	normalized.EnsureDefaults()

	status := api.SubjectsBySelectorGraphStatus{
		Selector:               normalized.Selector,
		ExpandedImplicitGroups: normalized.ExpandImplicitGroups,
		Graph:                  api.Graph{Nodes: []api.GraphNode{}, Edges: []api.GraphEdge{}},
	}

	candidates := snapshot.CandidateRoleIDs(normalized.Selector, normalized.WildcardMode)
	if len(candidates) == 0 {
		return status
	}

	g := newGraphBuilder()
	for _, roleID := range candidates {
		role, ok := snapshot.RolesByID[roleID]
		if !ok {
			continue
		}
		matchedRefs := matchRoleForGraphSelector(role, normalized)
		if len(matchedRefs) == 0 {
			continue
		}
		buildSelectorGraphForRole(g, role, matchedRefs, snapshot, normalized.ExpandImplicitGroups, e.ReportLookup)
	}

	graph := g.graph()
	status.Graph = graph
	status.MatchedRoles = countNodesOfTypes(graph.Nodes, api.GraphNodeTypeRole, api.GraphNodeTypeClusterRole)
	status.MatchedBindings = countNodesOfTypes(graph.Nodes, api.GraphNodeTypeRoleBinding, api.GraphNodeTypeClusterRoleBinding)
	status.MatchedSubjects = countNodesOfTypes(graph.Nodes, api.GraphNodeTypeUser, api.GraphNodeTypeGroup, api.GraphNodeTypeServiceAccount)

	return status
}

// buildSelectorGraphForRole emits role+binding+subject nodes and their edges into the builder.
func buildSelectorGraphForRole(
	g *graphBuilder,
	role *indexer.RoleRecord,
	matchedRefs []api.RuleRef,
	snapshot *indexer.Snapshot,
	expandImplicit bool,
	reportLookup ReportLookup,
) {
	roleNID := roleNodeID(role)
	g.addNode(api.GraphNode{
		ID:              roleNID,
		Type:            roleType(role),
		Name:            role.Name,
		Namespace:       role.Namespace,
		Labels:          role.Labels,
		Annotations:     role.Annotations,
		MatchedRuleRefs: append([]api.RuleRef(nil), matchedRefs...),
		Assessment:      lookupAssessmentForRole(reportLookup, role),
	})

	roleRefKey := indexer.RoleRefKey{Kind: role.Kind, Namespace: role.Namespace, Name: role.Name}
	for _, binding := range snapshot.BindingsByRoleRef[roleRefKey] {
		bindingNID := bindingNodeID(binding)
		g.addNode(api.GraphNode{
			ID:        bindingNID,
			Type:      bindingType(binding),
			Name:      binding.Name,
			Namespace: binding.Namespace,
		})
		g.addEdge(api.GraphEdge{
			ID:       edgeIDFor(bindingNID, roleNID, api.GraphEdgeTypeGrants),
			From:     bindingNID,
			To:       roleNID,
			Type:     api.GraphEdgeTypeGrants,
			RuleRefs: append([]api.RuleRef(nil), matchedRefs...),
			Explain:  edgeExplainGrants,
		})

		for _, subject := range binding.Subjects {
			literalRef := apiSubjectFromBindingSubject(subject, binding.Namespace)
			addSelectorSubjectEdge(g, literalRef, bindingNID)

			if !expandImplicit {
				continue
			}
			for _, expanded := range expandImplicitGroupToSAs(subject, snapshot) {
				addSelectorSubjectEdge(g, expanded, bindingNID)
			}
		}
	}
}

func addSelectorSubjectEdge(g *graphBuilder, ref api.SubjectRef, bindingNID string) {
	subjectNID := subjectRefNodeID(ref)
	g.addNode(api.GraphNode{
		ID:        subjectNID,
		Type:      subjectNodeTypeFromKind(ref.Kind),
		Name:      ref.Name,
		Namespace: ref.Namespace,
	})
	g.addEdge(api.GraphEdge{
		ID:      edgeIDFor(subjectNID, bindingNID, api.GraphEdgeTypeSubjects),
		From:    subjectNID,
		To:      bindingNID,
		Type:    api.GraphEdgeTypeSubjects,
		Explain: "binding targets subject",
	})
}

func matchRoleForGraphSelector(role *indexer.RoleRecord, spec api.SubjectsBySelectorGraphSpec) []api.RuleRef {
	refs := make([]api.RuleRef, 0)
	for idx, rule := range role.Rules {
		result := matcher.MatchRule(matcher.MatchInput{
			Rule:         rule,
			Selector:     spec.Selector,
			Mode:         spec.MatchMode,
			WildcardMode: spec.WildcardMode,
			SourceUID:    string(role.UID),
			RuleIndex:    idx,
		})
		if !result.Matched {
			continue
		}
		refs = append(refs, result.RuleRefs...)
	}

	return refs
}

func countNodesOfTypes(nodes []api.GraphNode, types ...api.GraphNodeType) int {
	if len(nodes) == 0 || len(types) == 0 {
		return 0
	}
	set := make(map[api.GraphNodeType]struct{}, len(types))
	for _, t := range types {
		set[t] = struct{}{}
	}
	n := 0
	for i := range nodes {
		if _, ok := set[nodes[i].Type]; ok {
			n++
		}
	}

	return n
}
