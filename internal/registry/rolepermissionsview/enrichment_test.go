package rolepermissionsview

import (
	"context"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	fake "k8s.io/client-go/kubernetes/fake"

	"k8s-rbac-engine/pkg/apis/rbacgraph"
	"k8s-rbac-engine/pkg/engine"
	"k8s-rbac-engine/pkg/indexer"
)

// newTestRESTWithLookup returns a REST handler with a populated mock
// ReportLookup. Use it for tests that need to assert on the
// Status.Assessment field.
func newTestRESTWithLookup(
	roles map[indexer.RoleID]*indexer.RoleRecord,
	lookup engine.ReportLookup,
) *REST {
	idx := indexer.New(fake.NewSimpleClientset(), 0)
	idx.SetSnapshotForTest(&indexer.Snapshot{RolesByID: roles})

	return NewREST(idx, lookup)
}

// TestCreate_Assessment_NilLookup confirms the Status.Assessment field is
// nil (and therefore omitted from JSON) when no ReportLookup is configured.
// This is the default behaviour for clusters without rbacreports CRDs.
func TestCreate_Assessment_NilLookup(t *testing.T) {
	r := newTestRESTWithLookup(
		map[indexer.RoleID]*indexer.RoleRecord{
			"clusterrole:viewer": {
				Kind: "ClusterRole",
				Name: "viewer",
				Rules: []rbacv1.PolicyRule{{
					APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"},
				}},
			},
		},
		nil, // explicit: no lookup
	)

	view := &rbacgraph.RolePermissionsView{
		Spec: rbacgraph.RolePermissionsViewSpec{
			Role: rbacgraph.RoleRef{Kind: "ClusterRole", Name: "viewer"},
		},
	}
	obj, err := r.Create(context.Background(), view, nil, &metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	got := obj.(*rbacgraph.RolePermissionsView)
	if got.Status.Assessment != nil {
		t.Errorf("expected Status.Assessment nil with no lookup, got %+v", got.Status.Assessment)
	}
}

// TestCreate_Assessment_ClusterRoleHit attaches an Assessment for a
// ClusterRole and verifies it lands in the response.
func TestCreate_Assessment_ClusterRoleHit(t *testing.T) {
	lookup := engine.NewMapReportLookup()
	lookup.Set(indexer.KindClusterRole, "", "cluster-admin",
		engine.AssessmentFromCounts(2, 1, 0, 0, []string{"KSV044", "KSV050", "KSV041"}))

	r := newTestRESTWithLookup(
		map[indexer.RoleID]*indexer.RoleRecord{
			"clusterrole:cluster-admin": {
				Kind: "ClusterRole",
				Name: "cluster-admin",
				Rules: []rbacv1.PolicyRule{{
					APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"},
				}},
			},
		},
		lookup,
	)

	view := &rbacgraph.RolePermissionsView{
		Spec: rbacgraph.RolePermissionsViewSpec{
			Role: rbacgraph.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
		},
	}
	obj, err := r.Create(context.Background(), view, nil, &metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	got := obj.(*rbacgraph.RolePermissionsView).Status.Assessment

	if got == nil {
		t.Fatalf("expected Status.Assessment to be populated")
	}
	if got.HighestSeverity != "CRITICAL" {
		t.Errorf("HighestSeverity = %q, want CRITICAL", got.HighestSeverity)
	}
	if got.CriticalCount != 2 || got.HighCount != 1 || got.TotalCount != 3 {
		t.Errorf("counts = %+v, want critical=2 high=1 total=3", got)
	}
	want := []string{"KSV041", "KSV044", "KSV050"}
	if len(got.CheckIDs) != 3 || got.CheckIDs[0] != want[0] || got.CheckIDs[1] != want[1] || got.CheckIDs[2] != want[2] {
		t.Errorf("CheckIDs = %v, want %v", got.CheckIDs, want)
	}
}

// TestCreate_Assessment_NamespacedRoleHit verifies that the namespace
// component of the lookup key is honored — a Role's assessment must not
// leak to a same-named ClusterRole and vice versa.
func TestCreate_Assessment_NamespacedRoleHit(t *testing.T) {
	lookup := engine.NewMapReportLookup()
	lookup.Set(indexer.KindRole, "istio-system", "istiod",
		engine.AssessmentFromCounts(0, 0, 1, 0, []string{"KSV049"}))

	r := newTestRESTWithLookup(
		map[indexer.RoleID]*indexer.RoleRecord{
			"role:istio-system/istiod": {
				Kind:      "Role",
				Namespace: "istio-system",
				Name:      "istiod",
				Rules: []rbacv1.PolicyRule{{
					APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"create"},
				}},
			},
		},
		lookup,
	)

	view := &rbacgraph.RolePermissionsView{
		Spec: rbacgraph.RolePermissionsViewSpec{
			Role: rbacgraph.RoleRef{Kind: "Role", Namespace: "istio-system", Name: "istiod"},
		},
	}
	obj, err := r.Create(context.Background(), view, nil, &metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	got := obj.(*rbacgraph.RolePermissionsView).Status.Assessment
	if got == nil {
		t.Fatalf("expected Assessment, got nil")
	}
	if got.HighestSeverity != "MEDIUM" {
		t.Errorf("HighestSeverity = %q, want MEDIUM", got.HighestSeverity)
	}
	if got.MediumCount != 1 || got.TotalCount != 1 {
		t.Errorf("counts = %+v, want medium=1 total=1", got)
	}
}

// TestCreate_Assessment_LookupMiss confirms a configured but empty lookup
// produces nil Assessment for unrelated roles — the field stays absent.
func TestCreate_Assessment_LookupMiss(t *testing.T) {
	lookup := engine.NewMapReportLookup()
	// Configured for some other role.
	lookup.Set(indexer.KindClusterRole, "", "different-role",
		engine.AssessmentFromCounts(1, 0, 0, 0, nil))

	r := newTestRESTWithLookup(
		map[indexer.RoleID]*indexer.RoleRecord{
			"clusterrole:viewer": {
				Kind: "ClusterRole", Name: "viewer",
				Rules: []rbacv1.PolicyRule{{
					APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"},
				}},
			},
		},
		lookup,
	)

	view := &rbacgraph.RolePermissionsView{
		Spec: rbacgraph.RolePermissionsViewSpec{
			Role: rbacgraph.RoleRef{Kind: "ClusterRole", Name: "viewer"},
		},
	}
	obj, err := r.Create(context.Background(), view, nil, &metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	got := obj.(*rbacgraph.RolePermissionsView).Status.Assessment
	if got != nil {
		t.Errorf("expected Assessment nil for lookup miss, got %+v", got)
	}
}
