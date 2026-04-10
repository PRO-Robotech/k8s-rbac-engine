package indexer

import (
	"slices"

	"k8s.io/apimachinery/pkg/types"
)

// Scoped returns a filtered copy of the snapshot that only contains
// RBAC objects the caller is allowed to see according to scope.
// If scope.IsUnrestricted(), the original snapshot is returned as-is (zero cost).
//
//nolint:gocognit,gocyclo // filtering each resource type is inherently repetitive
func Scoped(s *Snapshot, scope Scope) *Snapshot {
	if scope.IsUnrestricted() {
		return s
	}

	out := &Snapshot{
		BuiltAt:               s.BuiltAt,
		RolesByID:             make(map[RoleID]*RoleRecord, len(s.RolesByID)),
		BindingsByRoleRef:     make(map[RoleRefKey][]*BindingRecord, len(s.BindingsByRoleRef)),
		AggregatedRoleSources: make(map[RoleID][]RoleID, len(s.AggregatedRoleSources)),
		PodsByServiceAccount:  make(map[ServiceAccountKey][]*PodRecord, len(s.PodsByServiceAccount)),
		ServiceAccounts:       s.ServiceAccounts,
		WorkloadsByUID:        make(map[types.UID]*WorkloadRecord, len(s.WorkloadsByUID)),
		RoleIDsByVerb:         make(map[string]map[RoleID]struct{}),
		RoleIDsByResource:     make(map[string]map[RoleID]struct{}),
		RoleIDsByAPIGroup:     make(map[string]map[RoleID]struct{}),
		KnownGaps:             s.CloneKnownGaps(),
		Warnings:              s.CloneWarnings(),
	}

	for id, rec := range s.RolesByID {
		if scope.AllowRole(rec.Namespace) {
			out.RolesByID[id] = rec
			out.AllRoleIDs = append(out.AllRoleIDs, id)
			indexRoleTokens(out, id, rec.Rules)
		}
	}
	slices.Sort(out.AllRoleIDs)

	for key, bindings := range s.BindingsByRoleRef {
		var kept []*BindingRecord
		for _, b := range bindings {
			if scope.AllowBinding(b.Namespace) {
				kept = append(kept, b)
			}
		}
		if len(kept) > 0 {
			out.BindingsByRoleRef[key] = kept
		}
	}

	// Filter aggregated role sources — keep only if target role survived.
	for targetID, sources := range s.AggregatedRoleSources {
		if _, ok := out.RolesByID[targetID]; !ok {
			continue
		}
		var kept []RoleID
		for _, srcID := range sources {
			if _, ok := out.RolesByID[srcID]; ok {
				kept = append(kept, srcID)
			}
		}
		if len(kept) > 0 {
			out.AggregatedRoleSources[targetID] = kept
		}
	}

	for key, pods := range s.PodsByServiceAccount {
		var kept []*PodRecord
		for _, p := range pods {
			if scope.AllowPod(p.Namespace) {
				kept = append(kept, p)
			}
		}
		if len(kept) > 0 {
			out.PodsByServiceAccount[key] = kept
		}
	}

	for uid, w := range s.WorkloadsByUID {
		if scope.AllowWorkload(w.Namespace) {
			out.WorkloadsByUID[uid] = w
		}
	}

	return out
}
