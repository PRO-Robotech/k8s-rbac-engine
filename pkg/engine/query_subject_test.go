package engine_test

import (
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/types"

	api "k8s-rbac-engine/pkg/apis/rbacgraph"
	"k8s-rbac-engine/pkg/engine"
	"k8s-rbac-engine/pkg/indexer"
)

// buildReverseTestSnapshot creates a snapshot covering:
//   - ClusterRole "view" with rule {get/list pods, secrets}
//   - ClusterRole "impersonator" with rule {impersonate users, groups}
//   - Role ns-a/read-cm with rule {get configmaps}
//   - ClusterRoleBinding view-auth-crb: view → system:authenticated
//   - ClusterRoleBinding imp-crb: impersonator → User alice
//   - RoleBinding ns-a/foo-rb: read-cm → ServiceAccount ns-a/foo
//   - ClusterRoleBinding broken-crb: non-existent role → ServiceAccount ns-a/foo
func buildReverseTestSnapshot() *indexer.Snapshot {
	s := &indexer.Snapshot{
		RolesByID:         map[indexer.RoleID]*indexer.RoleRecord{},
		BindingsByRoleRef: map[indexer.RoleRefKey][]*indexer.BindingRecord{},
		BindingsBySubject: map[indexer.SubjectKey][]*indexer.BindingRecord{},
	}

	view := &indexer.RoleRecord{
		UID:  types.UID("cr-view"),
		Kind: indexer.KindClusterRole,
		Name: "view",
		Rules: []rbacv1.PolicyRule{{
			Verbs: []string{"get", "list"}, APIGroups: []string{""},
			Resources: []string{"pods", "secrets"},
		}},
		RuleCount: 1,
	}
	s.RolesByID[indexer.RecID(indexer.KindClusterRole, "", "view")] = view

	imp := &indexer.RoleRecord{
		UID:  types.UID("cr-imp"),
		Kind: indexer.KindClusterRole,
		Name: "impersonator",
		Rules: []rbacv1.PolicyRule{{
			Verbs: []string{"impersonate"}, APIGroups: []string{""},
			Resources: []string{"users", "groups"},
		}},
		RuleCount: 1,
	}
	s.RolesByID[indexer.RecID(indexer.KindClusterRole, "", "impersonator")] = imp

	readCM := &indexer.RoleRecord{
		UID: types.UID("role-readcm"), Kind: indexer.KindRole,
		Namespace: "ns-a", Name: "read-cm",
		Rules: []rbacv1.PolicyRule{{
			Verbs: []string{"get"}, APIGroups: []string{""},
			Resources: []string{"configmaps"},
		}},
		RuleCount: 1,
	}
	s.RolesByID[indexer.RecID(indexer.KindRole, "ns-a", "read-cm")] = readCM

	viewCRB := &indexer.BindingRecord{
		UID: types.UID("crb-view-auth"), Kind: indexer.KindClusterRoleBinding,
		Name:     "view-auth-crb",
		RoleRef:  indexer.RoleRefKey{Kind: indexer.KindClusterRole, Name: "view"},
		Subjects: []rbacv1.Subject{{Kind: indexer.SubjectKindGroup, Name: "system:authenticated"}},
	}
	s.BindingsByRoleRef[viewCRB.RoleRef] = []*indexer.BindingRecord{viewCRB}
	s.BindingsBySubject[indexer.SubjectKey{Kind: indexer.SubjectKindGroup, Name: "system:authenticated"}] = []*indexer.BindingRecord{viewCRB}

	impCRB := &indexer.BindingRecord{
		UID: types.UID("crb-imp"), Kind: indexer.KindClusterRoleBinding,
		Name:     "imp-crb",
		RoleRef:  indexer.RoleRefKey{Kind: indexer.KindClusterRole, Name: "impersonator"},
		Subjects: []rbacv1.Subject{{Kind: indexer.SubjectKindUser, Name: "alice"}},
	}
	s.BindingsByRoleRef[impCRB.RoleRef] = []*indexer.BindingRecord{impCRB}
	s.BindingsBySubject[indexer.SubjectKey{Kind: indexer.SubjectKindUser, Name: "alice"}] = []*indexer.BindingRecord{impCRB}

	fooRB := &indexer.BindingRecord{
		UID: types.UID("rb-foo"), Kind: indexer.KindRoleBinding,
		Namespace: "ns-a", Name: "foo-rb",
		RoleRef:  indexer.RoleRefKey{Kind: indexer.KindRole, Namespace: "ns-a", Name: "read-cm"},
		Subjects: []rbacv1.Subject{{Kind: indexer.SubjectKindServiceAccount, Namespace: "ns-a", Name: "foo"}},
	}
	s.BindingsByRoleRef[fooRB.RoleRef] = []*indexer.BindingRecord{fooRB}
	s.BindingsBySubject[indexer.SubjectKey{Kind: indexer.SubjectKindServiceAccount, Namespace: "ns-a", Name: "foo"}] = []*indexer.BindingRecord{fooRB}

	brokenCRB := &indexer.BindingRecord{
		UID: types.UID("crb-broken"), Kind: indexer.KindClusterRoleBinding,
		Name:     "broken-crb",
		RoleRef:  indexer.RoleRefKey{Kind: indexer.KindClusterRole, Name: "deleted-role"},
		Subjects: []rbacv1.Subject{{Kind: indexer.SubjectKindServiceAccount, Namespace: "ns-a", Name: "foo"}},
	}
	s.BindingsByRoleRef[brokenCRB.RoleRef] = []*indexer.BindingRecord{brokenCRB}
	s.BindingsBySubject[indexer.SubjectKey{Kind: indexer.SubjectKindServiceAccount, Namespace: "ns-a", Name: "foo"}] = append(
		s.BindingsBySubject[indexer.SubjectKey{Kind: indexer.SubjectKindServiceAccount, Namespace: "ns-a", Name: "foo"}],
		brokenCRB,
	)

	return s
}

func TestQuerySubjectPermissions_ServiceAccountExpandsImplicitGroups(t *testing.T) {
	s := buildReverseTestSnapshot()
	e := engine.New()

	status := e.QuerySubjectPermissions(s, api.SubjectPermissionsViewSpec{
		Subject: api.SubjectRef{Kind: api.SubjectKindServiceAccount, Namespace: "ns-a", Name: "foo"},
	}, nil)

	// Expect 4 resolved identities: SA + 3 implicit groups.
	if got := len(status.ResolvedSubjects); got != 4 {
		t.Fatalf("expected 4 resolved subjects (SA + implicit groups), got %d: %+v", got, status.ResolvedSubjects)
	}

	// Roles found: view (via system:authenticated), read-cm (direct). Plus phantom "deleted-role".
	if got := len(status.Roles); got != 3 {
		t.Fatalf("expected 3 role summaries, got %d: %+v", got, status.Roles)
	}

	// Bindings: view-auth-crb, foo-rb, broken-crb.
	if got := len(status.Bindings); got != 3 {
		t.Fatalf("expected 3 subject bindings, got %d: %+v", got, status.Bindings)
	}

	// Grants: from view (2 resources × 2 verbs = 4) + read-cm (1 × 1 = 1) = 5. Broken binding contributes nothing.
	if got := len(status.Grants); got != 5 {
		t.Fatalf("expected 5 attributed grants, got %d: %+v", got, status.Grants)
	}

	// apiGroups tree: single core group with {pods, secrets, configmaps}.
	if got := len(status.APIGroups); got != 1 {
		t.Fatalf("expected 1 apiGroup (core), got %d: %+v", got, status.APIGroups)
	}
	if got := len(status.APIGroups[0].Resources); got != 3 {
		t.Fatalf("expected 3 resources, got %d: %+v", got, status.APIGroups[0].Resources)
	}

	// Broken binding warning should be present.
	foundBroken := false
	for _, w := range status.Warnings {
		if w.Code == api.SubjectWarningCodeBrokenBinding {
			foundBroken = true

			break
		}
	}
	if !foundBroken {
		t.Errorf("expected BrokenBinding warning, got %+v", status.Warnings)
	}

	// The broken binding should show up in Bindings[] with Broken=true.
	foundBrokenBinding := false
	for _, b := range status.Bindings {
		if b.Name == "broken-crb" && b.Broken {
			foundBrokenBinding = true

			break
		}
	}
	if !foundBrokenBinding {
		t.Errorf("expected broken-crb in bindings with Broken=true, got %+v", status.Bindings)
	}
}

func TestQuerySubjectPermissions_DirectOnlySkipsImplicitGroups(t *testing.T) {
	s := buildReverseTestSnapshot()
	e := engine.New()

	status := e.QuerySubjectPermissions(s, api.SubjectPermissionsViewSpec{
		Subject:    api.SubjectRef{Kind: api.SubjectKindServiceAccount, Namespace: "ns-a", Name: "foo"},
		DirectOnly: true,
	}, nil)

	// Only the SA itself — no implicit groups.
	if got := len(status.ResolvedSubjects); got != 1 {
		t.Fatalf("expected 1 resolved subject in direct-only mode, got %d: %+v", got, status.ResolvedSubjects)
	}

	// With directOnly, view ClusterRole (via system:authenticated) is not reached.
	// Still see read-cm (direct) and broken-crb (direct).
	viewFound := false
	for _, r := range status.Roles {
		if r.Ref.Name == "view" {
			viewFound = true
		}
	}
	if viewFound {
		t.Errorf("expected 'view' role to NOT be reached in direct-only mode, got roles=%+v", status.Roles)
	}
}

func TestQuerySubjectPermissions_UserGetsAuthenticatedOnly(t *testing.T) {
	s := buildReverseTestSnapshot()
	e := engine.New()

	status := e.QuerySubjectPermissions(s, api.SubjectPermissionsViewSpec{
		Subject: api.SubjectRef{Kind: api.SubjectKindUser, Name: "alice"},
	}, nil)

	// User alice expands to [User:alice, Group:system:authenticated] — 2 identities.
	if got := len(status.ResolvedSubjects); got != 2 {
		t.Fatalf("expected 2 resolved subjects for user, got %d: %+v", got, status.ResolvedSubjects)
	}

	// Alice gets impersonator (direct) + view (via system:authenticated).
	if got := len(status.Roles); got != 2 {
		t.Fatalf("expected 2 roles for alice, got %d: %+v", got, status.Roles)
	}

	// Impersonation warning should fire.
	foundImp := false
	for _, w := range status.Warnings {
		if w.Code == api.SubjectWarningCodeImpersonationCapable {
			foundImp = true
			if len(w.Subjects) == 0 {
				t.Errorf("expected impersonation warning to list targets, got %+v", w)
			}

			break
		}
	}
	if !foundImp {
		t.Errorf("expected ImpersonationCapable warning, got %+v", status.Warnings)
	}
}

func TestQuerySubjectPermissions_GroupNoExpansion(t *testing.T) {
	s := buildReverseTestSnapshot()
	e := engine.New()

	status := e.QuerySubjectPermissions(s, api.SubjectPermissionsViewSpec{
		Subject: api.SubjectRef{Kind: api.SubjectKindGroup, Name: "system:authenticated"},
	}, nil)

	// Group queries do not expand — just the group itself.
	if got := len(status.ResolvedSubjects); got != 1 {
		t.Fatalf("expected 1 resolved subject for group, got %d: %+v", got, status.ResolvedSubjects)
	}

	// system:authenticated is bound to view only.
	if got := len(status.Roles); got != 1 || status.Roles[0].Ref.Name != "view" {
		t.Fatalf("expected single 'view' role, got %+v", status.Roles)
	}
}

func TestQuerySubjectPermissions_ZeroPermissionsReturnsEmpty(t *testing.T) {
	s := buildReverseTestSnapshot()
	e := engine.New()

	status := e.QuerySubjectPermissions(s, api.SubjectPermissionsViewSpec{
		Subject: api.SubjectRef{Kind: api.SubjectKindUser, Name: "bob"},
	}, nil)

	// Bob gets nothing (not bound anywhere), but system:authenticated group binding gives view.
	if got := len(status.Roles); got != 1 {
		t.Fatalf("expected 1 role (via system:authenticated), got %d: %+v", got, status.Roles)
	}
}

func TestQuerySubjectPermissions_AttributionPopulated(t *testing.T) {
	s := buildReverseTestSnapshot()
	e := engine.New()

	status := e.QuerySubjectPermissions(s, api.SubjectPermissionsViewSpec{
		Subject: api.SubjectRef{Kind: api.SubjectKindServiceAccount, Namespace: "ns-a", Name: "foo"},
	}, nil)

	for _, grant := range status.Grants {
		if grant.SourceRole.Name == "" {
			t.Errorf("expected SourceRole populated, got %+v", grant)
		}
		if grant.SourceBinding.Name == "" {
			t.Errorf("expected SourceBinding populated, got %+v", grant)
		}
	}

	// Find a "view" grant (via system:authenticated) and check its source.
	var viewGrant *api.AttributedGrant
	for i := range status.Grants {
		if status.Grants[i].SourceRole.Name == "view" {
			viewGrant = &status.Grants[i]

			break
		}
	}
	if viewGrant == nil {
		t.Fatalf("expected at least one grant from role 'view'")
	}
	if string(viewGrant.SourceBinding.Kind) != indexer.KindClusterRoleBinding {
		t.Errorf("expected SourceBinding.Kind=ClusterRoleBinding, got %q", viewGrant.SourceBinding.Kind)
	}
}

func TestQuerySubjectPermissions_EffectiveScope(t *testing.T) {
	s := buildReverseTestSnapshot()
	e := engine.New()

	status := e.QuerySubjectPermissions(s, api.SubjectPermissionsViewSpec{
		Subject: api.SubjectRef{Kind: api.SubjectKindServiceAccount, Namespace: "ns-a", Name: "foo"},
	}, nil)

	for _, b := range status.Bindings {
		switch b.Kind {
		case api.BindingKindClusterRoleBinding:
			if b.EffectiveScope != api.EffectiveScopeCluster {
				t.Errorf("CRB %q: expected cluster scope, got %q", b.Name, b.EffectiveScope)
			}
		case api.BindingKindRoleBinding:
			if b.EffectiveScope != api.EffectiveScopeNamespaced {
				t.Errorf("RB %q: expected namespaced scope, got %q", b.Name, b.EffectiveScope)
			}
		}
	}
}

func TestQuerySubjectGraph_BuildsNodesAndEdges(t *testing.T) {
	s := buildReverseTestSnapshot()
	e := engine.New()

	status := e.QuerySubjectGraph(s, api.SubjectGraphReviewSpec{
		Subject: api.SubjectRef{Kind: api.SubjectKindServiceAccount, Namespace: "ns-a", Name: "foo"},
	}, nil)

	if status.MatchedRoles < 2 {
		t.Errorf("expected >=2 matched roles, got %d", status.MatchedRoles)
	}
	if len(status.Graph.Nodes) == 0 {
		t.Fatal("expected non-empty graph nodes")
	}
	if len(status.Graph.Edges) == 0 {
		t.Fatal("expected non-empty graph edges")
	}

	// Subject node must be present.
	foundSubject := false
	for _, n := range status.Graph.Nodes {
		if n.Type == api.GraphNodeTypeServiceAccount && n.Name == "foo" && n.Namespace == "ns-a" {
			foundSubject = true

			break
		}
	}
	if !foundSubject {
		t.Errorf("expected subject node for ServiceAccount ns-a/foo, got nodes=%+v", status.Graph.Nodes)
	}

	// At least one edge of type "subjects" exists (subject → binding).
	foundSubjectEdge := false
	for _, ed := range status.Graph.Edges {
		if ed.Type == api.GraphEdgeTypeSubjects {
			foundSubjectEdge = true

			break
		}
	}
	if !foundSubjectEdge {
		t.Errorf("expected at least one 'subjects' edge, got edges=%+v", status.Graph.Edges)
	}
}

func TestQuerySubjectPermissions_AssessmentFromLookup(t *testing.T) {
	s := buildReverseTestSnapshot()
	lookup := engine.NewMapReportLookup()
	lookup.Set(indexer.KindClusterRole, "", "view", &api.Assessment{
		HighestSeverity: "HIGH",
		HighCount:       2,
		TotalCount:      2,
		CheckIDs:        []string{"KSV047"},
	})
	e := engine.New().WithReportLookup(lookup)

	status := e.QuerySubjectPermissions(s, api.SubjectPermissionsViewSpec{
		Subject: api.SubjectRef{Kind: api.SubjectKindServiceAccount, Namespace: "ns-a", Name: "foo"},
	}, nil)

	var viewRole *api.SubjectRoleSummary
	for i := range status.Roles {
		if status.Roles[i].Ref.Name == "view" {
			viewRole = &status.Roles[i]

			break
		}
	}
	if viewRole == nil {
		t.Fatal("expected view role summary in response")
	}
	if viewRole.Assessment == nil {
		t.Fatalf("expected assessment on view role, got nil")
	}
	if viewRole.Assessment.HighestSeverity != "HIGH" {
		t.Errorf("expected HIGH severity, got %q", viewRole.Assessment.HighestSeverity)
	}
}

func TestQuerySubjectPermissions_SelectorFiltersGrants(t *testing.T) {
	s := buildReverseTestSnapshot()
	e := engine.New()

	status := e.QuerySubjectPermissions(s, api.SubjectPermissionsViewSpec{
		Subject: api.SubjectRef{Kind: api.SubjectKindServiceAccount, Namespace: "ns-a", Name: "foo"},
		Selector: api.Selector{
			Resources: []string{"secrets"},
		},
	}, nil)

	// With selector resources=secrets, only view role's secrets grants survive.
	// read-cm (configmaps) and impersonator (users/groups) filtered out.
	for _, g := range status.Grants {
		if g.Resource != "secrets" {
			t.Errorf("unexpected grant for non-secrets resource: %+v", g)
		}
	}
	if len(status.Grants) == 0 {
		t.Error("expected at least one secrets grant from view role")
	}
}
