package engine

import (
	"fmt"
	"strings"

	rbacv1 "k8s.io/api/rbac/v1"

	api "k8s-rbac-engine/pkg/apis/rbacgraph"
	"k8s-rbac-engine/pkg/indexer"
)

// isPhantomSubject returns true if the subject is a ServiceAccount that is
// referenced by a binding but does not actually exist in the cluster. Users
// and Groups are never phantom because they come from authenticators and
// never exist as etcd objects by design.
func (qc *queryContext) isPhantomSubject(subject rbacv1.Subject) bool {
	if !strings.EqualFold(subject.Kind, indexer.SubjectKindServiceAccount) {
		return false
	}
	if qc.snapshot == nil || qc.snapshot.ServiceAccounts == nil {
		return false
	}
	_, exists := qc.snapshot.ServiceAccounts[indexer.ServiceAccountKey{
		Namespace: subject.Namespace,
		Name:      subject.Name,
	}]

	return !exists
}

//nolint:gocognit,gocyclo,funlen // core graph-building loop with necessary branching
func (qc *queryContext) buildRBACGraph(roleIDs []indexer.RoleID) {
	for _, roleID := range roleIDs {
		role, ok := qc.snapshot.RolesByID[roleID]
		if !ok {
			continue
		}
		if !allowNamespace(qc.namespaceFilter, role.Namespace, false) {
			continue
		}

		matches := qc.processMatches(matchRole(role, qc.spec))
		if len(matches) == 0 {
			continue
		}

		roleRefKey := indexer.RoleRefKey{Kind: role.Kind, Namespace: role.Namespace, Name: role.Name}
		bindings := qc.snapshot.BindingsByRoleRef[roleRefKey]
		filteredBindings := filterBindingsByNamespace(qc.namespaceFilter, qc.namespaceStrict, bindings)
		if qc.namespaceStrict && role.Namespace == "" && len(filteredBindings) == 0 {
			continue
		}

		roleNodeID := qc.upsertRoleNode(role, qc.snapshot.AggregatedRoleSources[roleID], matches)
		qc.roleSeen[roleID] = struct{}{}
		for _, sourceRoleID := range qc.snapshot.AggregatedRoleSources[roleID] {
			sourceRole, ok := qc.snapshot.RolesByID[sourceRoleID]
			if !ok {
				continue
			}

			sourceMatches := qc.processMatches(matchRole(sourceRole, qc.spec))
			if len(sourceMatches) == 0 {
				continue
			}

			sourceNodeID := qc.upsertRoleNode(sourceRole, qc.snapshot.AggregatedRoleSources[sourceRoleID], sourceMatches)
			qc.appendEdgeIfMissing(api.GraphEdge{
				ID:      edgeIDFor(sourceNodeID, roleNodeID, api.GraphEdgeTypeAggregates),
				From:    sourceNodeID,
				To:      roleNodeID,
				Type:    api.GraphEdgeTypeAggregates,
				Explain: edgeExplainAggregates,
			})
		}

		if len(filteredBindings) == 0 {
			qc.accumulateResourceRows(matches, roleID, "", "")

			continue
		}

		for _, binding := range filteredBindings {
			bindingNodeIDValue := bindingNodeID(binding)
			qc.addNodeIfMissing(api.GraphNode{
				ID:        bindingNodeIDValue,
				Type:      bindingType(binding),
				Name:      binding.Name,
				Namespace: binding.Namespace,
			})
			qc.bindingSeen[bindingNodeIDValue] = struct{}{}

			qc.appendEdgeIfMissing(api.GraphEdge{
				ID:       edgeIDFor(roleNodeID, bindingNodeIDValue, api.GraphEdgeTypeGrants),
				From:     roleNodeID,
				To:       bindingNodeIDValue,
				Type:     api.GraphEdgeTypeGrants,
				RuleRefs: matches,
				Explain:  edgeExplainGrants,
			})

			if len(binding.Subjects) == 0 {
				qc.accumulateResourceRows(matches, roleID, bindingNodeIDValue, "")

				continue
			}

			for _, subject := range binding.Subjects {
				subjectNodeIDValue := subjectNodeID(subject)
				phantom := qc.isPhantomSubject(subject)
				nodeNamespace := ""
				if subjectType(subject.Kind) == api.GraphNodeTypeServiceAccount {
					nodeNamespace = subject.Namespace
				}
				qc.addNodeIfMissing(api.GraphNode{
					ID:        subjectNodeIDValue,
					Type:      subjectType(subject.Kind),
					Name:      subject.Name,
					Namespace: nodeNamespace,
					Phantom:   phantom,
				})
				if phantom {
					qc.addWarning(fmt.Sprintf(
						"ServiceAccount %s/%s referenced by %s/%s does not exist in the cluster",
						subject.Namespace, subject.Name, binding.Kind, binding.Name,
					))
				}
				qc.subjectSeen[subjectNodeIDValue] = struct{}{}
				qc.trackServiceAccountSubject(subjectNodeIDValue, subject, binding.Namespace)

				qc.appendEdgeIfMissing(api.GraphEdge{
					ID:      edgeIDFor(bindingNodeIDValue, subjectNodeIDValue, api.GraphEdgeTypeSubjects),
					From:    bindingNodeIDValue,
					To:      subjectNodeIDValue,
					Type:    api.GraphEdgeTypeSubjects,
					Explain: edgeExplainSubjects,
				})

				qc.accumulateResourceRows(matches, roleID, bindingNodeIDValue, subjectNodeIDValue)
			}
		}
	}
}

func (qc *queryContext) processMatches(refs []api.RuleRef) []api.RuleRef {
	if qc.discovery == nil {
		return refs
	}
	annotatePhantomRefs(refs, qc.discovery, qc.addWarning)
	if qc.spec.FilterPhantomAPIs {
		refs = filterPhantomRefs(refs)
	}
	expandWildcardRefs(refs, qc.discovery, qc.addWarning)
	annotateUnsupportedVerbs(refs, qc.discovery)

	return refs
}

func filterPhantomRefs(refs []api.RuleRef) []api.RuleRef {
	filtered := make([]api.RuleRef, 0, len(refs))
	for i := range refs {
		if !refs[i].Phantom {
			filtered = append(filtered, refs[i])
		}
	}

	return filtered
}
