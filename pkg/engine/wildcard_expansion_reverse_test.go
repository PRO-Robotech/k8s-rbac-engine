package engine

import (
	"strings"
	"testing"
	"time"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/types"

	api "k8s-rbac-engine/pkg/apis/rbacgraph"
	"k8s-rbac-engine/pkg/indexer"
)

// With discovery, both grants[] and the apiGroups[] tree show concrete tuples,
// never a literal "*".
func TestReverseExpansion_SubjectPermissionsView_GrantsAndTree(t *testing.T) {
	snapshot := buildClusterAdminLikeSnapshot()
	discovery := buildSmallDiscovery()

	status := New().QuerySubjectPermissions(snapshot, api.SubjectPermissionsViewSpec{
		Subject: api.SubjectRef{Kind: api.SubjectKindUser, Name: "alice"},
	}, discovery)

	if len(status.Grants) <= 1 {
		t.Fatalf("expected expansion to produce >1 grants, got %d", len(status.Grants))
	}
	for _, g := range status.Grants {
		if g.APIGroup == "*" || g.Resource == "*" || g.Verb == "*" {
			t.Errorf("found unexpanded wildcard in grant: %+v", g)
		}
	}

	if len(status.APIGroups) == 0 {
		t.Fatal("expected expanded apiGroups tree, got empty")
	}
	for _, ag := range status.APIGroups {
		if ag.APIGroup == "*" {
			t.Errorf("apiGroups tree still shows wildcard apiGroup: %+v", ag)
		}
		for _, r := range ag.Resources {
			if r.Plural == "*" {
				t.Errorf("apiGroups tree still shows wildcard resource: %+v", r)
			}
			for v := range r.Verbs {
				if v == "*" {
					t.Errorf("apiGroups tree still shows wildcard verb: %s/%s/%s", ag.APIGroup, r.Plural, v)
				}
			}
		}
	}
}

// The graph projection must inline ExpandedRefs into role nodes' matchedRuleRefs.
func TestReverseExpansion_SubjectGraphReview_NodesCarryExpandedRefs(t *testing.T) {
	snapshot := buildClusterAdminLikeSnapshot()
	discovery := buildSmallDiscovery()

	status := New().QuerySubjectGraph(snapshot, api.SubjectGraphReviewSpec{
		Subject: api.SubjectRef{Kind: api.SubjectKindUser, Name: "alice"},
	}, discovery)

	foundExpanded := false
	for _, node := range status.Graph.Nodes {
		for _, ref := range node.MatchedRuleRefs {
			if len(ref.ExpandedRefs) > 0 {
				foundExpanded = true
				for _, ex := range ref.ExpandedRefs {
					if ex.APIGroup == "*" || ex.Resource == "*" || ex.Verb == "*" {
						t.Errorf("ExpandedRef contains wildcard: %+v", ex)
					}
				}
			}
		}
	}
	if !foundExpanded {
		t.Fatal("expected at least one role node with non-empty ExpandedRefs")
	}
}

// TestReverseExpansion_SubjectsBySelectorView_PerSubjectExpansion verifies
// that selector-based reverse query also expands wildcards.
func TestReverseExpansion_SubjectsBySelectorView_PerSubjectExpansion(t *testing.T) {
	snapshot := buildClusterAdminLikeSnapshot()
	// Add SAs so expandImplicitGroups paths see something (not needed for this
	// test but documents fixture state).
	snapshot.ServiceAccounts = map[indexer.ServiceAccountKey]struct{}{
		{Namespace: "default", Name: "foo"}: {},
	}
	// Token indexes so CandidateRoleIDs finds the wildcard role.
	id := indexer.RecID(indexer.KindClusterRole, "", "cluster-admin")
	snapshot.RoleIDsByAPIGroup["*"] = map[indexer.RoleID]struct{}{id: {}}
	snapshot.RoleIDsByResource["*"] = map[indexer.RoleID]struct{}{id: {}}
	snapshot.RoleIDsByVerb["*"] = map[indexer.RoleID]struct{}{id: {}}
	discovery := buildSmallDiscovery()

	status := New().QuerySubjectsBySelector(snapshot, api.SubjectsBySelectorViewSpec{
		Selector: api.Selector{Resources: []string{"pods"}, Verbs: []string{"get"}},
	}, discovery)

	if len(status.Subjects) == 0 {
		t.Fatal("expected at least one subject")
	}
	for _, s := range status.Subjects {
		for _, g := range s.Grants {
			if g.APIGroup == "*" || g.Resource == "*" || g.Verb == "*" {
				t.Errorf("subject %s has unexpanded grant: %+v", s.Subject.Name, g)
			}
		}
	}
}

// Selector-graph nodes must carry ExpandedRefs in matchedRuleRefs.
func TestReverseExpansion_SubjectsBySelectorGraph_ExpandedRefsInNodes(t *testing.T) {
	snapshot := buildClusterAdminLikeSnapshot()
	id := indexer.RecID(indexer.KindClusterRole, "", "cluster-admin")
	snapshot.RoleIDsByAPIGroup["*"] = map[indexer.RoleID]struct{}{id: {}}
	snapshot.RoleIDsByResource["*"] = map[indexer.RoleID]struct{}{id: {}}
	snapshot.RoleIDsByVerb["*"] = map[indexer.RoleID]struct{}{id: {}}
	discovery := buildSmallDiscovery()

	status := New().QuerySubjectsBySelectorGraph(snapshot, api.SubjectsBySelectorGraphSpec{
		Selector: api.Selector{Resources: []string{"pods"}, Verbs: []string{"get"}},
	}, discovery)

	foundExpanded := false
	for _, node := range status.Graph.Nodes {
		for _, ref := range node.MatchedRuleRefs {
			if len(ref.ExpandedRefs) > 0 {
				foundExpanded = true
			}
		}
	}
	if !foundExpanded {
		t.Fatal("expected ExpandedRefs in at least one node")
	}
}

// Without discovery, wildcards must stay as literals.
func TestReverseExpansion_NilDiscoveryPreservesLiterals(t *testing.T) {
	snapshot := buildClusterAdminLikeSnapshot()

	status := New().QuerySubjectPermissions(snapshot, api.SubjectPermissionsViewSpec{
		Subject: api.SubjectRef{Kind: api.SubjectKindUser, Name: "alice"},
	}, nil) // ← nil discovery

	if len(status.Grants) != 1 {
		t.Fatalf("expected exactly 1 wildcard grant without discovery, got %d", len(status.Grants))
	}
	g := status.Grants[0]
	if g.APIGroup != "*" || g.Resource != "*" || g.Verb != "*" {
		t.Errorf("expected literal */*/* grant without discovery, got %+v", g)
	}
}

// TestReverseExpansion_FilterPhantomAPIsRemovesMismatched verifies that the
// FilterPhantomAPIs spec flag interacts correctly with expansion: phantom
// refs (apiGroup not in discovery) are dropped BEFORE expansion runs.
func TestReverseExpansion_FilterPhantomAPIsRemovesMismatched(t *testing.T) {
	// Role grants a phantom apiGroup; nothing else.
	snapshot := &indexer.Snapshot{
		BuiltAt:           time.Now(),
		RolesByID:         map[indexer.RoleID]*indexer.RoleRecord{},
		BindingsByRoleRef: map[indexer.RoleRefKey][]*indexer.BindingRecord{},
		BindingsBySubject: map[indexer.SubjectKey][]*indexer.BindingRecord{},
		RoleIDsByVerb:     map[string]map[indexer.RoleID]struct{}{},
		RoleIDsByResource: map[string]map[indexer.RoleID]struct{}{},
		RoleIDsByAPIGroup: map[string]map[indexer.RoleID]struct{}{},
		AllRoleIDs:        []indexer.RoleID{},
	}
	role := &indexer.RoleRecord{
		UID:  types.UID("r1"),
		Kind: indexer.KindClusterRole,
		Name: "phantom-role",
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{"never-installed.example.com"},
			Resources: []string{"pods"},
			Verbs:     []string{"get"},
		}},
	}
	rid := indexer.RecID(indexer.KindClusterRole, "", "phantom-role")
	snapshot.RolesByID[rid] = role
	snapshot.AllRoleIDs = []indexer.RoleID{rid}

	binding := &indexer.BindingRecord{
		UID:      types.UID("b1"),
		Kind:     indexer.KindClusterRoleBinding,
		Name:     "bind",
		RoleRef:  indexer.RoleRefKey{Kind: indexer.KindClusterRole, Name: "phantom-role"},
		Subjects: []rbacv1.Subject{{Kind: indexer.SubjectKindUser, Name: "alice"}},
	}
	snapshot.BindingsByRoleRef[binding.RoleRef] = []*indexer.BindingRecord{binding}
	snapshot.BindingsBySubject[indexer.SubjectKey{Kind: indexer.SubjectKindUser, Name: "alice"}] = []*indexer.BindingRecord{binding}

	discovery := buildSmallDiscovery() // doesn't know never-installed.example.com

	status := New().QuerySubjectPermissions(snapshot, api.SubjectPermissionsViewSpec{
		Subject:           api.SubjectRef{Kind: api.SubjectKindUser, Name: "alice"},
		FilterPhantomAPIs: true,
	}, discovery)

	for _, g := range status.Grants {
		if g.APIGroup == "never-installed.example.com" {
			t.Errorf("phantom apiGroup leaked through FilterPhantomAPIs=true: %+v", g)
		}
	}
	// With filter on AND only phantom rule present, role still appears in
	// Roles[] but Grants[] should be empty.
	if len(status.Grants) != 0 {
		t.Errorf("expected 0 grants after phantom filter (only phantom rule existed), got %d", len(status.Grants))
	}
}

func TestTruncationAccumulator_Dedupes(t *testing.T) {
	acc := newTruncationAccumulator()
	if acc.result() != nil {
		t.Fatal("expected nil result before any emit")
	}

	acc.emit("wildcard expansion for */*/* truncated at 2000 entries")
	acc.emit("wildcard expansion for */*/* truncated at 2000 entries") // dup
	acc.emit("wildcard expansion for */pods/* truncated at 2000 entries")

	result := acc.result()
	if result == nil {
		t.Fatal("expected non-nil ExpansionTruncation after emits")
	}
	if got := len(result.Messages); got != 2 {
		t.Fatalf("expected 2 unique messages after dedup, got %d: %+v", got, result.Messages)
	}
	if result.Limit != maxExpandedRefsPerParent {
		t.Errorf("expected limit %d, got %d", maxExpandedRefsPerParent, result.Limit)
	}
}

// Overflow must land in status.ExpansionTruncated, never in warnings.
func TestReverseExpansion_TruncationWarningEndToEnd(t *testing.T) {
	snapshot := buildClusterAdminLikeSnapshot()
	// Discovery cache large enough to overflow the cap (3 groups × ~700 resources × 1 verb = 2100).
	discovery := buildLargeDiscovery(700)

	status := New().QuerySubjectPermissions(snapshot, api.SubjectPermissionsViewSpec{
		Subject: api.SubjectRef{Kind: api.SubjectKindUser, Name: "alice"},
	}, discovery)

	if status.ExpansionTruncated == nil {
		t.Fatalf("expected ExpansionTruncated to be set when discovery exceeds cap, got nil (warnings=%+v)", status.Warnings)
	}
	if status.ExpansionTruncated.Limit != maxExpandedRefsPerParent {
		t.Errorf("expected limit %d, got %d", maxExpandedRefsPerParent, status.ExpansionTruncated.Limit)
	}
	if len(status.ExpansionTruncated.Messages) == 0 {
		t.Error("expected at least one truncation message")
	}
	// Truncation must not leak back into the generic warnings list.
	for _, w := range status.Warnings {
		if strings.Contains(w.Message, "truncated") {
			t.Errorf("truncation message leaked into warnings: %+v", w)
		}
	}
}

// buildLargeDiscovery returns a discovery cache with `resourcesPerGroup`
// distinct resources in each of 3 groups — large enough to overflow
// maxExpandedRefsPerParent when matched against a `*/*/*` rule.
func buildLargeDiscovery(resourcesPerGroup int) *indexer.APIDiscoveryCache {
	groups := []string{"", "apps", "rbac.authorization.k8s.io"}
	disc := &indexer.APIDiscoveryCache{
		Groups:               make(map[string]struct{}),
		ResourcesByGroup:     make(map[string]map[string]struct{}),
		VerbsByGroupResource: make(map[string]map[string][]string),
		AllResources:         make(map[string]struct{}),
		AllVerbs:             map[string]struct{}{"get": {}},
		FetchedAt:            time.Now(),
	}
	for _, g := range groups {
		disc.Groups[g] = struct{}{}
		disc.ResourcesByGroup[g] = make(map[string]struct{}, resourcesPerGroup)
		disc.VerbsByGroupResource[g] = make(map[string][]string, resourcesPerGroup)
		for i := range resourcesPerGroup {
			name := "resource" + itoa(i)
			disc.ResourcesByGroup[g][name] = struct{}{}
			disc.VerbsByGroupResource[g][name] = []string{"get"}
			disc.AllResources[name] = struct{}{}
		}
	}

	return disc
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	digits := ""
	for n > 0 {
		digits = string(rune('0'+n%10)) + digits
		n /= 10
	}

	return digits
}
