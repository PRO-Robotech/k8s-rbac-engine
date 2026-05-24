package engine

import (
	"fmt"
	"sort"
	"strings"

	api "k8s-rbac-engine/pkg/apis/rbacgraph"
	"k8s-rbac-engine/pkg/indexer"
)

// maxExpandedRefsPerParent caps wildcard expansion per source rule ref to
// prevent runaway response sizes for roles like cluster-admin (*/*/*).
const maxExpandedRefsPerParent = 2000

// annotatePhantomRefs marks RuleRefs that reference apiGroups, resources, or
// subresources missing from cluster discovery. Refs without subresource fall
// back to base-resource lookup for graceful degradation; refs with explicit
// subresource require an exact discovery match.
//
//nolint:gocognit,gocyclo // multi-condition discovery validation
func annotatePhantomRefs(refs []api.RuleRef, discovery *indexer.APIDiscoveryCache, addWarning func(string)) {
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

		groupResources, groupExists := discovery.ResourcesByGroup[ref.APIGroup]
		if !groupExists {
			ref.Phantom = true
			addWarning(fmt.Sprintf(
				"API group %q referenced in role rules is not installed in the cluster",
				ref.APIGroup,
			))

			continue
		}

		lookupResource := ref.Resource
		hasSubresource := ref.Subresource != "" || strings.Contains(ref.Resource, "/")
		if ref.Subresource != "" && !strings.Contains(ref.Resource, "/") {
			lookupResource = ref.Resource + "/" + ref.Subresource
		}
		if lookupResource == "" {
			continue
		}
		if _, resourceExists := groupResources[lookupResource]; resourceExists {
			continue
		}
		if hasSubresource {
			// Subresource explicitly requested — full key is authoritative.
			// Base-resource fallback would falsely accept e.g. metrics.k8s.io/pods/exec
			// when only metrics.k8s.io/pods (PodMetrics) exists in discovery.
			ref.Phantom = true
			addWarning(fmt.Sprintf(
				"subresource %q in API group %q is not registered in the cluster",
				lookupResource, ref.APIGroup,
			))

			continue
		}
		// No subresource — fall back to base resource lookup for graceful
		// degradation when discovery omits some entries.
		baseResource := ref.Resource
		if idx := strings.Index(baseResource, "/"); idx >= 0 {
			baseResource = baseResource[:idx]
		}
		if _, baseExists := groupResources[baseResource]; !baseExists {
			ref.Phantom = true
			addWarning(fmt.Sprintf(
				"resource %q in API group %q is not registered in the cluster",
				lookupResource, ref.APIGroup,
			))
		}
	}
}

// expandWildcardRefs populates ref.ExpandedRefs with concrete (group, resource,
// verb) tuples derived from discovery. Truncates at maxExpandedRefsPerParent
// and emits a warning if so.
func expandWildcardRefs(refs []api.RuleRef, discovery *indexer.APIDiscoveryCache, addWarning func(string)) {
	for i := range refs {
		ref := &refs[i]

		if ref.APIGroup != "*" && ref.Resource != "*" && ref.Verb != "*" {
			continue
		}
		if ref.APIGroup == "" && ref.Resource == "" && len(ref.NonResourceURLs) > 0 {
			continue
		}

		expanded := resolveWildcardRef(ref, discovery)
		if len(expanded) > maxExpandedRefsPerParent {
			expanded = expanded[:maxExpandedRefsPerParent]
			addWarning(fmt.Sprintf(
				"wildcard expansion for %s/%s/%s truncated at %d entries",
				ref.APIGroup, ref.Resource, ref.Verb, maxExpandedRefsPerParent,
			))
		}
		if len(expanded) > 0 {
			ref.ExpandedRefs = expanded
		}
	}
}

// annotateUnsupportedVerbs flags refs whose verb is not in the supported list
// for the resource (per discovery). When the resource doesn't exist in any
// considered group at all, UnsupportedVerb remains false — phantom annotation
// owns that case.
//
//nolint:gocognit,gocyclo // multi-group verb validation
func annotateUnsupportedVerbs(refs []api.RuleRef, discovery *indexer.APIDiscoveryCache) {
	for i := range refs {
		ref := &refs[i]
		if ref.Verb == "*" || ref.Verb == "" {
			continue
		}
		resource := ref.Resource
		if ref.Subresource != "" {
			resource = ref.Resource + "/" + ref.Subresource
		}
		groups := []string{ref.APIGroup}
		if ref.APIGroup == "*" {
			groups = ResolveDiscoveryGroups("*", discovery)
		}
		supported := false
		resourceFound := false
		for _, group := range groups {
			groupVerbs, ok := discovery.VerbsByGroupResource[group]
			if !ok {
				continue
			}
			verbs, ok := groupVerbs[resource]
			if !ok {
				continue
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
		ref.UnsupportedVerb = resourceFound && !supported
	}
}

// resolveWildcardRef expands a single wildcard ref to a list of concrete refs
// based on discovery. Honors maxExpandedRefsPerParent as an early-exit limit.
func resolveWildcardRef(ref *api.RuleRef, discovery *indexer.APIDiscoveryCache) []api.RuleRef {
	groups := ResolveDiscoveryGroups(ref.APIGroup, discovery)
	var result []api.RuleRef

	for _, group := range groups {
		resources := ResolveDiscoveryResources(group, ref.Resource, discovery)
		for _, resource := range resources {
			fullResource := resource
			if ref.Subresource != "" {
				fullResource = resource + "/" + ref.Subresource
			}
			verbs := ResolveDiscoveryVerbs(group, fullResource, ref.Verb, discovery)
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

// ResolveDiscoveryGroups returns the apiGroup as-is when concrete, or the
// full set of groups in discovery when the input is "*".
func ResolveDiscoveryGroups(apiGroup string, discovery *indexer.APIDiscoveryCache) []string {
	if apiGroup != "*" {
		return []string{apiGroup}
	}
	groups := make([]string, 0, len(discovery.ResourcesByGroup))
	for g := range discovery.ResourcesByGroup {
		groups = append(groups, g)
	}
	sort.Strings(groups)

	return groups
}

// ResolveDiscoveryResources returns the resource as-is when concrete, or the
// full set of resources for the group when input is "*".
func ResolveDiscoveryResources(group, resource string, discovery *indexer.APIDiscoveryCache) []string {
	if resource != "*" {
		return []string{resource}
	}
	groupResources := discovery.ResourcesByGroup[group]
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

// ResolveDiscoveryVerbs resolves a verb against discovery's supported list.
func ResolveDiscoveryVerbs(group, resource, verb string, discovery *indexer.APIDiscoveryCache) []string {
	groupVerbs, groupKnown := discovery.VerbsByGroupResource[group]

	if verb != "*" {
		if !groupKnown {
			return []string{verb}
		}
		supported, resourceKnown := groupVerbs[resource]
		if !resourceKnown {
			return nil
		}
		for _, v := range supported {
			if strings.EqualFold(v, verb) {
				return []string{verb}
			}
		}

		return nil
	}

	if !groupKnown {
		verbs := make([]string, 0, len(discovery.AllVerbs))
		for v := range discovery.AllVerbs {
			verbs = append(verbs, v)
		}
		sort.Strings(verbs)

		return verbs
	}
	if verbs, ok := groupVerbs[resource]; ok {
		return verbs
	}

	return nil
}

// IsResourceInDiscovery returns true when the (apiGroup, resource) tuple is
// registered in discovery.
func IsResourceInDiscovery(discovery *indexer.APIDiscoveryCache, apiGroup, resource string) bool {
	if discovery == nil || apiGroup == "*" || resource == "*" {
		return true
	}
	groupResources, ok := discovery.ResourcesByGroup[apiGroup]
	if !ok {
		return false
	}
	_, exists := groupResources[resource]

	return exists
}

// IsVerbSupportedByDiscovery returns true when the verb is in the supported
// list for (apiGroup, resource).
func IsVerbSupportedByDiscovery(discovery *indexer.APIDiscoveryCache, apiGroup, resource, verb string) bool {
	if discovery == nil {
		return true
	}
	groupVerbs, groupKnown := discovery.VerbsByGroupResource[apiGroup]
	if !groupKnown {
		return true
	}
	supported, resourceKnown := groupVerbs[resource]
	if !resourceKnown {
		return true
	}
	for _, v := range supported {
		if strings.EqualFold(v, verb) {
			return true
		}
	}

	return false
}
