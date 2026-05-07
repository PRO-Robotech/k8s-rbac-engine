package engine

import (
	"slices"
	"strings"

	rbacv1 "k8s.io/api/rbac/v1"

	api "k8s-rbac-engine/pkg/apis/rbacgraph"
	"k8s-rbac-engine/pkg/indexer"
	"k8s-rbac-engine/pkg/matcher"
)

// QuerySubjectsBySelector returns subjects matching the selector, with role and binding provenance per grant.
func (e *Engine) QuerySubjectsBySelector(
	snapshot *indexer.Snapshot,
	spec api.SubjectsBySelectorViewSpec,
	_ *indexer.APIDiscoveryCache,
) api.SubjectsBySelectorViewStatus {
	normalized := spec
	normalized.EnsureDefaults()

	status := api.SubjectsBySelectorViewStatus{
		Selector:               normalized.Selector,
		ExpandedImplicitGroups: normalized.ExpandImplicitGroups,
		Subjects:               []api.ScopedSubject{},
	}

	candidates := snapshot.CandidateRoleIDs(normalized.Selector, normalized.WildcardMode)
	if len(candidates) == 0 {
		return status
	}

	agg := newScopedSubjectAggregator(e.ReportLookup)
	for _, roleID := range candidates {
		role, ok := snapshot.RolesByID[roleID]
		if !ok {
			continue
		}
		matchedRefs := matchRoleAgainstSelectorSpec(role, normalized)
		if len(matchedRefs) == 0 {
			continue
		}
		collectSubjectsForRole(role, matchedRefs, snapshot, normalized.ExpandImplicitGroups, agg)
	}

	status.Subjects = agg.finalize()

	return status
}

// collectSubjectsForRole records grants for each subject of every binding that references the role.
func collectSubjectsForRole(
	role *indexer.RoleRecord,
	matchedRefs []api.RuleRef,
	snapshot *indexer.Snapshot,
	expandImplicit bool,
	agg *scopedSubjectAggregator,
) {
	roleRefKey := indexer.RoleRefKey{Kind: role.Kind, Namespace: role.Namespace, Name: role.Name}
	bindings := snapshot.BindingsByRoleRef[roleRefKey]
	sourceRole := roleRefFromRecord(role)

	for _, binding := range bindings {
		sourceBinding := bindingRefFromRecord(binding)
		for _, subject := range binding.Subjects {
			literalRef := apiSubjectFromBindingSubject(subject, binding.Namespace)
			agg.add(literalRef, role, sourceRole, sourceBinding, matchedRefs)

			if !expandImplicit {
				continue
			}
			for _, expanded := range expandImplicitGroupToSAs(subject, snapshot) {
				agg.add(expanded, role, sourceRole, sourceBinding, matchedRefs)
			}
		}
	}
}

func matchRoleAgainstSelectorSpec(role *indexer.RoleRecord, spec api.SubjectsBySelectorViewSpec) []api.RuleRef {
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

// apiSubjectFromBindingSubject defaults bare ServiceAccount namespaces to the binding's namespace,
// matching kube-apiserver's authorization-time resolution.
func apiSubjectFromBindingSubject(s rbacv1.Subject, bindingNamespace string) api.SubjectRef {
	ns := s.Namespace
	if s.Kind == indexer.SubjectKindServiceAccount && ns == "" {
		ns = bindingNamespace
	}

	return api.SubjectRef{
		Kind:      api.SubjectKind(s.Kind),
		Name:      s.Name,
		Namespace: ns,
	}
}

// expandImplicitGroupToSAs resolves system:serviceaccounts* and system:authenticated to concrete SAs from the snapshot.
func expandImplicitGroupToSAs(s rbacv1.Subject, snapshot *indexer.Snapshot) []api.SubjectRef {
	if s.Kind != indexer.SubjectKindGroup {
		return nil
	}
	switch {
	case s.Name == groupSystemAuthenticated, s.Name == groupAllServiceAccounts:
		out := make([]api.SubjectRef, 0, len(snapshot.ServiceAccounts))
		for key := range snapshot.ServiceAccounts {
			out = append(out, api.SubjectRef{
				Kind:      api.SubjectKindServiceAccount,
				Namespace: key.Namespace,
				Name:      key.Name,
			})
		}

		return out
	case strings.HasPrefix(s.Name, groupServiceAccountsPrefix):
		ns := strings.TrimPrefix(s.Name, groupServiceAccountsPrefix)
		out := make([]api.SubjectRef, 0)
		for key := range snapshot.ServiceAccounts {
			if key.Namespace == ns {
				out = append(out, api.SubjectRef{
					Kind:      api.SubjectKindServiceAccount,
					Namespace: key.Namespace,
					Name:      key.Name,
				})
			}
		}

		return out
	}

	return nil
}

// scopedSubjectAggregator accumulates per-subject grants and per-role assessments.
type scopedSubjectAggregator struct {
	reportLookup ReportLookup
	subjects     map[indexer.SubjectKey]*scopedSubjectAcc
	order        []indexer.SubjectKey
}

type scopedSubjectAcc struct {
	ref       api.SubjectRef
	grants    []api.AttributedGrant
	roleSet   map[indexer.RoleID]*api.Assessment
	grantSeen map[grantDedupeKey]struct{}
}

type grantDedupeKey struct {
	sourceRoleKind string
	sourceRoleNs   string
	sourceRoleName string
	sourceBindKind string
	sourceBindNs   string
	sourceBindName string
	apiGroup       string
	resource       string
	verb           string
	nonResourceURL string
}

func newScopedSubjectAggregator(rl ReportLookup) *scopedSubjectAggregator {
	return &scopedSubjectAggregator{
		reportLookup: rl,
		subjects:     make(map[indexer.SubjectKey]*scopedSubjectAcc),
	}
}

func (a *scopedSubjectAggregator) add(
	ref api.SubjectRef,
	role *indexer.RoleRecord,
	sourceRole api.RoleRef,
	sourceBinding api.BindingRef,
	matchedRefs []api.RuleRef,
) {
	key := indexer.SubjectKey{
		Kind: string(ref.Kind), Namespace: ref.Namespace, Name: ref.Name,
	}
	acc, ok := a.subjects[key]
	if !ok {
		acc = &scopedSubjectAcc{
			ref:       ref,
			roleSet:   make(map[indexer.RoleID]*api.Assessment),
			grantSeen: make(map[grantDedupeKey]struct{}),
		}
		a.subjects[key] = acc
		a.order = append(a.order, key)
	}
	roleID := indexer.RecID(role.Kind, role.Namespace, role.Name)
	if _, seen := acc.roleSet[roleID]; !seen {
		acc.roleSet[roleID] = lookupAssessmentForRole(a.reportLookup, role)
	}
	for i := range matchedRefs {
		grant := attributedGrantFromRef(&matchedRefs[i], sourceRole, sourceBinding)
		gk := grantDedupeKey{
			sourceRoleKind: string(grant.SourceRole.Kind),
			sourceRoleNs:   grant.SourceRole.Namespace,
			sourceRoleName: grant.SourceRole.Name,
			sourceBindKind: string(grant.SourceBinding.Kind),
			sourceBindNs:   grant.SourceBinding.Namespace,
			sourceBindName: grant.SourceBinding.Name,
			apiGroup:       grant.APIGroup,
			resource:       grant.Resource,
			verb:           grant.Verb,
			nonResourceURL: grant.NonResourceURL,
		}
		if _, dup := acc.grantSeen[gk]; dup {
			continue
		}
		acc.grantSeen[gk] = struct{}{}
		acc.grants = append(acc.grants, grant)
	}
}

func (a *scopedSubjectAggregator) finalize() []api.ScopedSubject {
	slices.SortFunc(a.order, compareSubjectKey)
	out := make([]api.ScopedSubject, 0, len(a.subjects))
	for _, k := range a.order {
		acc := a.subjects[k]
		slices.SortFunc(acc.grants, compareAttributedGrant)
		out = append(out, api.ScopedSubject{
			Subject:    acc.ref,
			Grants:     acc.grants,
			Assessment: aggregateAssessments(acc.roleSet),
		})
	}

	return out
}

func compareSubjectKey(a, b indexer.SubjectKey) int {
	if a.Kind != b.Kind {
		if a.Kind < b.Kind {
			return -1
		}

		return 1
	}
	if a.Namespace != b.Namespace {
		if a.Namespace < b.Namespace {
			return -1
		}

		return 1
	}
	if a.Name < b.Name {
		return -1
	}
	if a.Name > b.Name {
		return 1
	}

	return 0
}

// aggregateAssessments sums per-role severity counts; returns nil when no role had a report.
func aggregateAssessments(roleSet map[indexer.RoleID]*api.Assessment) *api.Assessment {
	var (
		critical, high, medium, low int
		anyFound                    bool
	)
	seen := make(map[string]struct{})
	checkIDs := make([]string, 0)
	for _, a := range roleSet {
		if a == nil {
			continue
		}
		anyFound = true
		critical += a.CriticalCount
		high += a.HighCount
		medium += a.MediumCount
		low += a.LowCount
		for _, id := range a.CheckIDs {
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			checkIDs = append(checkIDs, id)
		}
	}
	if !anyFound {
		return nil
	}

	return AssessmentFromCounts(critical, high, medium, low, checkIDs)
}
