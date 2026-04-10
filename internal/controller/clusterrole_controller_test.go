package controller

import (
	"context"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"k8s-rbac-engine/pkg/apis/rbacreports/v1alpha1"
)

func clusterAdminRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cluster-admin",
			UID:  types.UID("cluster-admin-uid"),
		},
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{"*"},
			Resources: []string{"*"},
			Verbs:     []string{"*"},
		}},
	}
}

func ksv044Policy() *v1alpha1.RbacPolicy {
	return &v1alpha1.RbacPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "ksv044"},
		Spec: v1alpha1.RbacPolicySpec{
			Severity:    v1alpha1.SeverityCritical,
			Category:    "Kubernetes Security Check",
			CheckID:     "KSV044",
			Title:       "No wildcard verb and resource roles",
			Description: "Wildcard verbs/resources grant unrestricted access.",
			TargetKinds: []string{v1alpha1.KindClusterRole},
			Match: v1alpha1.Match{
				MatchMode: v1alpha1.MatchModeExact,
				APIGroups: []string{"*"},
				Resources: []string{"*"},
				Verbs:     []string{"*"},
			},
		},
	}
}

func reconcileClusterRole(ctx context.Context, t *testing.T, r *ClusterRoleReconciler, role *rbacv1.ClusterRole) {
	t.Helper()
	res, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: role.Name}})
	if err != nil {
		t.Fatalf("Reconcile error: %v", err)
	}
	if res != (ctrl.Result{}) {
		t.Errorf("expected empty Result, got %+v", res)
	}
}

// TestClusterRoleReconciler_CreatesReport exercises the happy path against
// the KSV044 "literal wildcard" policy.
func TestClusterRoleReconciler_CreatesReport(t *testing.T) {
	ctx := context.Background()
	role := clusterAdminRole()
	c := newClient(t, role, ksv044Policy())

	r := &ClusterRoleReconciler{Client: c}
	reconcileClusterRole(ctx, t, r, role)

	var got v1alpha1.ClusterRbacReport
	if err := c.Get(ctx, types.NamespacedName{Name: "cluster-admin"}, &got); err != nil {
		t.Fatalf("get ClusterRbacReport: %v", err)
	}

	if got.Namespace != "" {
		t.Errorf("ClusterRbacReport must be cluster-scoped, got namespace %q", got.Namespace)
	}
	if got.Spec.RoleRef.Kind != v1alpha1.KindClusterRole {
		t.Errorf("RoleRef.Kind = %q", got.Spec.RoleRef.Kind)
	}
	if len(got.Report.Checks) != 1 {
		t.Fatalf("expected 1 check, got %d", len(got.Report.Checks))
	}
	if got.Report.Checks[0].CheckID != "KSV044" {
		t.Errorf("CheckID = %q", got.Report.Checks[0].CheckID)
	}
	if got.Report.Summary.CriticalCount != 1 {
		t.Errorf("CriticalCount = %d, want 1", got.Report.Summary.CriticalCount)
	}

	// Owner reference must point at the ClusterRole.
	if len(got.OwnerReferences) != 1 {
		t.Fatalf("expected 1 ownerReference")
	}
	or := got.OwnerReferences[0]
	if or.Kind != v1alpha1.KindClusterRole || or.Name != "cluster-admin" || or.UID != "cluster-admin-uid" {
		t.Errorf("ownerRef = %+v", or)
	}
}

// TestClusterRoleReconciler_TargetKindsFilter confirms that a policy
// targeting only Role does NOT produce a violation against a ClusterRole.
func TestClusterRoleReconciler_TargetKindsFilter(t *testing.T) {
	ctx := context.Background()
	role := clusterAdminRole()
	policy := ksv044Policy()
	policy.Spec.TargetKinds = []string{v1alpha1.KindRole} // misconfigured for cluster-admin

	c := newClient(t, role, policy)
	r := &ClusterRoleReconciler{Client: c}
	reconcileClusterRole(ctx, t, r, role)

	var got v1alpha1.ClusterRbacReport
	if err := c.Get(ctx, types.NamespacedName{Name: "cluster-admin"}, &got); err != nil {
		t.Fatalf("get report: %v", err)
	}
	if len(got.Report.Checks) != 0 {
		t.Errorf("policy with TargetKinds=[Role] must not match ClusterRole; got %d checks", len(got.Report.Checks))
	}
}

// TestClusterRoleReconciler_DeletedRoleIsNoOp mirrors the Role test for the
// cluster-scoped reconciler.
func TestClusterRoleReconciler_DeletedRoleIsNoOp(t *testing.T) {
	ctx := context.Background()
	c := newClient(t)
	r := &ClusterRoleReconciler{Client: c}

	res, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "missing"}})
	if err != nil {
		t.Fatalf("expected nil error for missing ClusterRole, got %v", err)
	}
	if res != (ctrl.Result{}) {
		t.Errorf("expected empty Result, got %+v", res)
	}

	var list v1alpha1.ClusterRbacReportList
	if err := c.List(ctx, &list); err != nil {
		t.Fatalf("list reports: %v", err)
	}
	if len(list.Items) != 0 {
		t.Errorf("expected 0 reports, got %d", len(list.Items))
	}
}

// TestEnqueueAllClusterRoles_FanOut covers the cluster-scoped fan-out helper.
func TestEnqueueAllClusterRoles_FanOut(t *testing.T) {
	roles := []client.Object{
		&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "view"}},
		&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "edit"}},
	}
	c := newClient(t, roles...)

	got := enqueueAllClusterRoles(context.Background(), c)
	if len(got) != 2 {
		t.Fatalf("expected 2 requests, got %d", len(got))
	}

	want := map[reconcile.Request]bool{
		{NamespacedName: types.NamespacedName{Name: "view"}}: true,
		{NamespacedName: types.NamespacedName{Name: "edit"}}: true,
	}
	for _, req := range got {
		if !want[req] {
			t.Errorf("unexpected request %+v", req)
		}
	}
}
