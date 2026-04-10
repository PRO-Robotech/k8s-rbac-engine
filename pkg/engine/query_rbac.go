package engine

import (
	"fmt"
	"sort"
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

		matches := matchRole(role, qc.spec)
		if qc.discovery != nil {
			qc.annotatePhantomRefs(matches)
			if qc.spec.FilterPhantomAPIs {
				matches = filterPhantomRefs(matches)
			}
			qc.expandWildcardRefs(matches)
			qc.annotateUnsupportedVerbs(matches)
		}
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

			sourceMatches := matchRole(sourceRole, qc.spec)
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

//nolint:gocognit,gocyclo // multi-condition validation logic
func (qc *queryContext) annotatePhantomRefs(refs []api.RuleRef) {
	for i := range refs {
		ref := &refs[i]

		// NonResourceURL-only refs have no API group to validate.
		if ref.APIGroup == "" && ref.Resource == "" && len(ref.NonResourceURLs) > 0 {
			continue
		}
		// Wildcards can always match something — never phantom.
		if ref.APIGroup == "*" || ref.Resource == "*" {
			continue
		}

		groupResources, groupExists := qc.discovery.ResourcesByGroup[ref.APIGroup]
		if !groupExists {
			ref.Phantom = true
			qc.addWarning(fmt.Sprintf(
				"API group %q referenced in role rules is not installed in the cluster",
				ref.APIGroup,
			))

			continue
		}

		// Check resource (using "resource/subresource" form for lookup).
		lookupResource := ref.Resource
		if ref.Subresource != "" && !strings.Contains(ref.Resource, "/") {
			lookupResource = ref.Resource + "/" + ref.Subresource
		}
		if lookupResource != "" { //nolint:nestif // multi-level resource/subresource lookup
			if _, resourceExists := groupResources[lookupResource]; !resourceExists {
				baseResource := ref.Resource
				if idx := strings.Index(baseResource, "/"); idx >= 0 {
					baseResource = baseResource[:idx]
				}
				if _, baseExists := groupResources[baseResource]; !baseExists {
					ref.Phantom = true
					qc.addWarning(fmt.Sprintf(
						"resource %q in API group %q is not registered in the cluster",
						lookupResource, ref.APIGroup,
					))
				}
			}
		}
	}
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

const maxExpandedRefsPerParent = 2000

func (qc *queryContext) expandWildcardRefs(refs []api.RuleRef) {
	for i := range refs {
		ref := &refs[i]

		if ref.APIGroup != "*" && ref.Resource != "*" && ref.Verb != "*" {
			continue
		}
		if ref.APIGroup == "" && ref.Resource == "" && len(ref.NonResourceURLs) > 0 {
			continue
		}

		expanded := qc.resolveWildcardRef(ref)
		if len(expanded) > maxExpandedRefsPerParent {
			expanded = expanded[:maxExpandedRefsPerParent]
			qc.addWarning(fmt.Sprintf(
				"wildcard expansion for %s/%s/%s truncated at %d entries",
				ref.APIGroup, ref.Resource, ref.Verb, maxExpandedRefsPerParent,
			))
		}
		if len(expanded) > 0 {
			ref.ExpandedRefs = expanded
		}
	}
}

//nolint:gocognit,gocyclo // multi-group verb validation
func (qc *queryContext) annotateUnsupportedVerbs(refs []api.RuleRef) {
	for i := range refs {
		ref := &refs[i]
		if ref.Verb == "*" || ref.Verb == "" {
			continue
		}
		resource := ref.Resource
		if ref.Subresource != "" {
			resource = ref.Resource + "/" + ref.Subresource
		}
		// Determine the set of groups to check. For apiGroup=* we check all
		// groups that actually contain this resource.
		groups := []string{ref.APIGroup}
		if ref.APIGroup == "*" {
			groups = qc.resolveGroups("*")
		}
		supported := false
		resourceFound := false
		for _, group := range groups {
			groupVerbs, ok := qc.discovery.VerbsByGroupResource[group]
			if !ok {
				continue // group not in discovery — skip
			}
			verbs, ok := groupVerbs[resource]
			if !ok {
				continue // resource not in this group — skip
			}
			resourceFound = true
			for _, v := range verbs {
				if strings.EqualFold(v, ref.Verb) {
					supported = true

					break
				}
			}
			if supported {
				break
			}
		}
		// Only flag as unsupported when the resource exists in discovery
		// but the verb is not in any group's supported verb list.
		ref.UnsupportedVerb = resourceFound && !supported
	}
}

func (qc *queryContext) resolveWildcardRef(ref *api.RuleRef) []api.RuleRef {
	groups := qc.resolveGroups(ref.APIGroup)
	var result []api.RuleRef

	for _, group := range groups {
		resources := qc.resolveResources(group, ref.Resource)
		for _, resource := range resources {
			// Use the full resource key (e.g. "pods/exec") for discovery lookups
			// so that verb validation is against the actual subresource, not the parent.
			fullResource := resource
			if ref.Subresource != "" {
				fullResource = resource + "/" + ref.Subresource
			}
			verbs := qc.resolveVerbs(group, fullResource, ref.Verb)
			for _, verb := range verbs {
				result = append(result, api.RuleRef{
					APIGroup:      group,
					Resource:      resource,
					Subresource:   ref.Subresource,
					Verb:          verb,
					ResourceNames: ref.ResourceNames,
				})
				if len(result) > maxExpandedRefsPerParent {
					return result
				}
			}
		}
	}

	return result
}

func (qc *queryContext) resolveGroups(apiGroup string) []string {
	if apiGroup != "*" {
		return []string{apiGroup}
	}
	groups := make([]string, 0, len(qc.discovery.ResourcesByGroup))
	for g := range qc.discovery.ResourcesByGroup {
		groups = append(groups, g)
	}
	sort.Strings(groups)

	return groups
}

func (qc *queryContext) resolveResources(group, resource string) []string {
	if resource != "*" {
		return []string{resource}
	}
	groupResources := qc.discovery.ResourcesByGroup[group]
	if len(groupResources) == 0 {
		return nil
	}
	resources := make([]string, 0, len(groupResources))
	for r := range groupResources {
		resources = append(resources, r)
	}
	sort.Strings(resources)

	return resources
}

func (qc *queryContext) resolveVerbs(group, resource, verb string) []string {
	groupVerbs, groupKnown := qc.discovery.VerbsByGroupResource[group]

	if verb != "*" {
		if !groupKnown {
			return []string{verb} // group not in discovery — pass through (graceful degradation)
		}
		supported, resourceKnown := groupVerbs[resource]
		if !resourceKnown {
			return nil // group known, resource doesn't exist in it
		}
		for _, v := range supported {
			if strings.EqualFold(v, verb) {
				return []string{verb}
			}
		}

		return nil // verb not supported by this resource
	}

	// verb == "*"
	if !groupKnown {
		// Group unknown — fall back to all known verbs (graceful degradation).
		verbs := make([]string, 0, len(qc.discovery.AllVerbs))
		for v := range qc.discovery.AllVerbs {
			verbs = append(verbs, v)
		}
		sort.Strings(verbs)

		return verbs
	}
	if verbs, ok := groupVerbs[resource]; ok {
		return verbs // already sorted during cache build
	}

	return nil // group known, resource doesn't exist in it
}
