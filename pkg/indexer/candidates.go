package indexer

import (
	"slices"
	"strings"

	api "k8s-rbac-engine/pkg/apis/rbacgraph"
)

func (s *Snapshot) CandidateRoleIDs(selector api.Selector, wildcardMode api.WildcardMode) []RoleID {
	exactMode := wildcardMode == api.WildcardModeExact
	constraints := make([]map[RoleID]struct{}, 0, 3)

	if len(selector.APIGroups) > 0 {
		constraints = append(constraints, s.collectMatches(s.RoleIDsByAPIGroup, selector.APIGroups, exactMode))
	}
	if len(selector.Resources) > 0 {
		constraints = append(constraints, s.collectMatches(s.RoleIDsByResource, selector.Resources, exactMode))
	}
	if len(selector.Verbs) > 0 {
		constraints = append(constraints, s.collectMatches(s.RoleIDsByVerb, selector.Verbs, exactMode))
	}

	if len(constraints) == 0 {
		out := make([]RoleID, len(s.AllRoleIDs))
		copy(out, s.AllRoleIDs)

		return out
	}

	intersected := constraints[0]
	for i := 1; i < len(constraints); i++ {
		intersected = intersect(intersected, constraints[i])
		if len(intersected) == 0 {
			return nil
		}
	}

	out := make([]RoleID, 0, len(intersected))
	for roleID := range intersected {
		out = append(out, roleID)
	}
	slices.Sort(out)

	return out
}

func (s *Snapshot) collectMatches(index map[string]map[RoleID]struct{}, requested []string, exactMode bool) map[RoleID]struct{} {
	matches := make(map[RoleID]struct{})
	for _, token := range requested {
		n := strings.ToLower(strings.TrimSpace(token))
		if bucket, ok := index[n]; ok {
			for roleID := range bucket {
				matches[roleID] = struct{}{}
			}
		}
		// In wildcard mode, also include roles from the "*" wildcard bucket
		// (roles with wildcard rules). In exact mode, skip this unless the
		// requested token is literally "*".
		if !exactMode && n != "*" {
			if bucket, ok := index["*"]; ok {
				for roleID := range bucket {
					matches[roleID] = struct{}{}
				}
			}
		}
	}

	return matches
}

func intersect(left, right map[RoleID]struct{}) map[RoleID]struct{} {
	if len(left) > len(right) {
		left, right = right, left
	}
	out := make(map[RoleID]struct{})
	for roleID := range left {
		if _, ok := right[roleID]; ok {
			out[roleID] = struct{}{}
		}
	}

	return out
}
