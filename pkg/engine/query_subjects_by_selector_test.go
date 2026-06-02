package engine_test

import (
	"strings"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/types"

	api "k8s-rbac-engine/pkg/apis/rbacgraph"
	"k8s-rbac-engine/pkg/engine"
	"k8s-rbac-engine/pkg/indexer"
)

// indexTokensForTest mirrors the unexported indexRoleTokens for cross-package tests.
func indexTokensForTest(s *indexer.Snapshot, roleID indexer.RoleID, rules []rbacv1.PolicyRule) {
	if s.RoleIDsByVerb == nil {
		s.RoleIDsByVerb = make(map[string]map[indexer.RoleID]struct{})
	}
	if s.RoleIDsByResource == nil {
		s.RoleIDsByResource = make(map[string]map[indexer.RoleID]struct{})
	}
	if s.RoleIDsByAPIGroup == nil {
		s.RoleIDsByAPIGroup = make(map[string]map[indexer.RoleID]struct{})
	}
	insert := func(idx map[string]map[indexer.RoleID]struct{}, token string, id indexer.RoleID) {
		bucket, ok := idx[token]
		if !ok {
			bucket = make(map[indexer.RoleID]struct{})
			idx[token] = bucket
		}
		bucket[id] = struct{}{}
	}
	norm := func(v string) string { return strings.ToLower(strings.TrimSpace(v)) }
	for _, rule := range rules {
		for _, g := range rule.APIGroups {
			insert(s.RoleIDsByAPIGroup, norm(g), roleID)
		}
		for _, r := range rule.Resources {
			if r == "" {
				continue
			}
			insert(s.RoleIDsByResource, norm(r), roleID)
		}
		for _, v := range rule.Verbs {
			if v == "" {
				continue
			}
			insert(s.RoleIDsByVerb, norm(v), roleID)
		}
	}
}

// buildSelectorTestSnapshot extends the reverse fixture with token indexes used by CandidateRoleIDs.
func buildSelectorTestSnapshot() *indexer.Snapshot {
	s := buildReverseTestSnapshot()
	for id, role := range s.RolesByID {
		indexTokensForTest(s, id, role.Rules)
	}

	return s
}

// extendSnapshotWithServiceAccounts seeds SAs for virtual-group expansion tests.
func extendSnapshotWithServiceAccounts(s *indexer.Snapshot) {
	if s.ServiceAccounts == nil {
		s.ServiceAccounts = make(map[indexer.ServiceAccountKey]struct{})
	}
	s.ServiceAccounts[indexer.ServiceAccountKey{Namespace: "ns-a", Name: "foo"}] = struct{}{}
	s.ServiceAccounts[indexer.ServiceAccountKey{Namespace: "ns-a", Name: "bar"}] = struct{}{}
	s.ServiceAccounts[indexer.ServiceAccountKey{Namespace: "ns-b", Name: "baz"}] = struct{}{}
}

func TestQuerySubjectsBySelector_BasicLiteralSubjects(t *testing.T) {
	s := buildSelectorTestSnapshot()
	e := engine.New()

	status := e.QuerySubjectsBySelector(s, api.SubjectsBySelectorViewSpec{
		Selector: api.Selector{Resources: []string{"secrets"}, Verbs: []string{"get"}},
	}, nil)

	if !findSubject(status.Subjects, api.SubjectKindGroup, "", "system:authenticated") {
		t.Errorf("expected literal Group system:authenticated in subjects, got %+v", subjectNames(status.Subjects))
	}
	if status.ExpandedImplicitGroups {
		t.Error("expected expandedImplicitGroups=false by default")
	}
	for _, ss := range status.Subjects {
		if len(ss.Grants) == 0 {
			t.Errorf("subject %+v has zero grants — should never happen", ss.Subject)
		}
	}
}

func TestQuerySubjectsBySelector_ExpandResolvesGroupToConcreteSAs(t *testing.T) {
	s := buildSelectorTestSnapshot()
	extendSnapshotWithServiceAccounts(s)
	e := engine.New()

	status := e.QuerySubjectsBySelector(s, api.SubjectsBySelectorViewSpec{
		Selector:             api.Selector{Resources: []string{"secrets"}, Verbs: []string{"get"}},
		ExpandImplicitGroups: true,
	}, nil)

	if !status.ExpandedImplicitGroups {
		t.Error("expected expandedImplicitGroups=true to round-trip in status")
	}

	for _, key := range []struct {
		ns, name string
	}{{"ns-a", "foo"}, {"ns-a", "bar"}, {"ns-b", "baz"}} {
		if !findSubject(status.Subjects, api.SubjectKindServiceAccount, key.ns, key.name) {
			t.Errorf("expected expanded SA %s/%s, got %+v", key.ns, key.name, subjectNames(status.Subjects))
		}
	}

	if !findSubject(status.Subjects, api.SubjectKindGroup, "", "system:authenticated") {
		t.Error("expected literal Group system:authenticated to remain alongside expanded SAs (Users not enumerable)")
	}
}

func TestQuerySubjectsBySelector_LiteralSubjectsFromBindings(t *testing.T) {
	s := buildSelectorTestSnapshot()
	e := engine.New()

	status := e.QuerySubjectsBySelector(s, api.SubjectsBySelectorViewSpec{
		Selector: api.Selector{Resources: []string{"users", "groups"}, Verbs: []string{"impersonate"}},
	}, nil)

	if !findSubject(status.Subjects, api.SubjectKindUser, "", "alice") {
		t.Errorf("expected User alice (bound to impersonator CR), got %+v", subjectNames(status.Subjects))
	}
}

func TestQuerySubjectsBySelector_GrantAttribution(t *testing.T) {
	s := buildSelectorTestSnapshot()
	e := engine.New()

	status := e.QuerySubjectsBySelector(s, api.SubjectsBySelectorViewSpec{
		Selector: api.Selector{Resources: []string{"secrets"}, Verbs: []string{"get"}},
	}, nil)

	for _, ss := range status.Subjects {
		for _, g := range ss.Grants {
			if g.SourceRole.Name == "" {
				t.Errorf("subject %+v: SourceRole empty in grant %+v", ss.Subject, g)
			}
			if g.SourceBinding.Name == "" {
				t.Errorf("subject %+v: SourceBinding empty in grant %+v", ss.Subject, g)
			}
		}
	}
}

func TestQuerySubjectsBySelector_AssessmentAggregation(t *testing.T) {
	s := buildSelectorTestSnapshot()
	lookup := engine.NewMapReportLookup()
	lookup.Set(indexer.KindClusterRole, "", "view", &api.Assessment{
		HighestSeverity: "HIGH",
		HighCount:       2, TotalCount: 2,
		CheckIDs: []string{"KSV047"},
	})
	e := engine.New().WithReportLookup(lookup)

	status := e.QuerySubjectsBySelector(s, api.SubjectsBySelectorViewSpec{
		Selector: api.Selector{Resources: []string{"secrets"}, Verbs: []string{"get"}},
	}, nil)

	for _, ss := range status.Subjects {
		if ss.Subject.Kind == api.SubjectKindGroup && ss.Subject.Name == "system:authenticated" {
			if ss.Assessment == nil {
				t.Fatal("expected assessment on subject reachable via view role")
			}
			if ss.Assessment.HighestSeverity != "HIGH" {
				t.Errorf("expected HIGH, got %q", ss.Assessment.HighestSeverity)
			}

			return
		}
	}
	t.Error("subject system:authenticated not found")
}

func TestQuerySubjectsBySelector_EmptyMatch(t *testing.T) {
	s := buildSelectorTestSnapshot()
	e := engine.New()

	status := e.QuerySubjectsBySelector(s, api.SubjectsBySelectorViewSpec{
		Selector: api.Selector{Resources: []string{"nonexistent"}, Verbs: []string{"get"}},
	}, nil)

	if len(status.Subjects) != 0 {
		t.Errorf("expected zero subjects for non-matching selector, got %d", len(status.Subjects))
	}
}

func TestQuerySubjectsBySelector_GrantDedup(t *testing.T) {
	s := &indexer.Snapshot{
		RolesByID:         map[indexer.RoleID]*indexer.RoleRecord{},
		BindingsByRoleRef: map[indexer.RoleRefKey][]*indexer.BindingRecord{},
	}
	role := &indexer.RoleRecord{
		UID: types.UID("cr-1"), Kind: indexer.KindClusterRole, Name: "viewer",
		Rules: []rbacv1.PolicyRule{{
			Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"pods"},
		}},
	}
	s.RolesByID[indexer.RecID(indexer.KindClusterRole, "", "viewer")] = role

	binding := &indexer.BindingRecord{
		UID: types.UID("crb-1"), Kind: indexer.KindClusterRoleBinding, Name: "viewer-crb",
		RoleRef: indexer.RoleRefKey{Kind: indexer.KindClusterRole, Name: "viewer"},
		Subjects: []rbacv1.Subject{
			{Kind: indexer.SubjectKindUser, Name: "alice"},
			{Kind: indexer.SubjectKindUser, Name: "alice"},
		},
	}
	s.BindingsByRoleRef[binding.RoleRef] = []*indexer.BindingRecord{binding}

	e := engine.New()
	status := e.QuerySubjectsBySelector(s, api.SubjectsBySelectorViewSpec{
		Selector: api.Selector{Resources: []string{"pods"}, Verbs: []string{"get"}},
	}, nil)

	for _, ss := range status.Subjects {
		if ss.Subject.Name == "alice" && len(ss.Grants) != 1 {
			t.Errorf("expected 1 grant after dedup, got %d: %+v", len(ss.Grants), ss.Grants)
		}
	}
}

// helpers

func findSubject(subjects []api.ScopedSubject, kind api.SubjectKind, ns, name string) bool {
	for _, ss := range subjects {
		if ss.Subject.Kind == kind && ss.Subject.Namespace == ns && ss.Subject.Name == name {
			return true
		}
	}

	return false
}

func subjectNames(subjects []api.ScopedSubject) []string {
	out := make([]string, 0, len(subjects))
	for _, ss := range subjects {
		ns := ss.Subject.Namespace
		if ns == "" {
			out = append(out, string(ss.Subject.Kind)+":"+ss.Subject.Name)
		} else {
			out = append(out, string(ss.Subject.Kind)+":"+ns+"/"+ss.Subject.Name)
		}
	}

	return out
}
