package controller

import (
	"context"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"k8s-rbac-engine/pkg/apis/rbacreports/v1alpha1"
)

// testScheme registers the rbac.authorization.k8s.io/v1 builtins (so the
// fake client can serialize Role/ClusterRole) plus our rbacreports types.
func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := scheme.AddToScheme(s); err != nil {
		t.Fatalf("add core scheme: %v", err)
	}
	if err := v1alpha1.AddToScheme(s); err != nil {
		t.Fatalf("add rbacreports scheme: %v", err)
	}

	return s
}

// newClient builds a fake client.Client preloaded with the given objects.
// Important: we declare RbacReport.Status as an indexed field so List
// queries by ownerReference work — but we don't actually need that here
// because the reconciler always does a direct Get on the report by name.
func newClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()

	return fake.NewClientBuilder().
		WithScheme(testScheme(t)).
		WithObjects(objs...).
		Build()
}

func ksv049Policy() *v1alpha1.RbacPolicy {
	return &v1alpha1.RbacPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "ksv049"},
		Spec: v1alpha1.RbacPolicySpec{
			Severity:    v1alpha1.SeverityMedium,
			Category:    "Kubernetes Security Check",
			CheckID:     "KSV049",
			Title:       "Manage configmaps",
			Description: "Role has permission to manage configmaps.",
			Remediation: "Remove write verbs on configmaps.",
			Match: v1alpha1.Match{
				MatchMode: v1alpha1.MatchModeWildcard,
				APIGroups: []string{""},
				Resources: []string{"configmaps"},
				Verbs:     []string{"create", "update", "patch", "delete"},
			},
		},
	}
}

func istiodRole() *rbacv1.Role {
	return &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "istiod",
			Namespace: "istio-system",
			UID:       types.UID("istiod-uid"),
		},
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{""},
			Resources: []string{"configmaps"},
			Verbs:     []string{"create", "update"},
		}},
	}
}

func reconcileRole(ctx context.Context, t *testing.T, r *RoleReconciler, role *rbacv1.Role) {
	t.Helper()
	res, err := r.Reconcile(ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: role.Namespace, Name: role.Name},
	})
	if err != nil {
		t.Fatalf("Reconcile error: %v", err)
	}
	if res != (ctrl.Result{}) {
		t.Errorf("expected empty Result, got %+v", res)
	}
}

// TestRoleReconciler_CreatesReportOnFirstReconcile is the happy-path test:
// a Role with a violation produces a fresh RbacReport.
func TestRoleReconciler_CreatesReportOnFirstReconcile(t *testing.T) {
	ctx := context.Background()
	role := istiodRole()
	policy := ksv049Policy()
	c := newClient(t, role, policy)

	r := &RoleReconciler{Client: c}
	reconcileRole(ctx, t, r, role)

	var got v1alpha1.RbacReport
	err := c.Get(ctx, types.NamespacedName{Namespace: "istio-system", Name: "istiod"}, &got)
	if err != nil {
		t.Fatalf("expected RbacReport to exist after reconcile: %v", err)
	}

	if got.Spec.RoleRef.Name != "istiod" {
		t.Errorf("RoleRef.Name = %q, want istiod", got.Spec.RoleRef.Name)
	}
	if len(got.Report.Checks) != 1 {
		t.Fatalf("expected 1 check, got %d", len(got.Report.Checks))
	}
	if got.Report.Checks[0].CheckID != "KSV049" {
		t.Errorf("CheckID = %q", got.Report.Checks[0].CheckID)
	}
	if got.Report.Summary.MediumCount != 1 || got.Report.Summary.TotalCount != 1 {
		t.Errorf("Summary = %+v, want medium=1 total=1", got.Report.Summary)
	}

	// Owner reference should point at the role with controller=true.
	if len(got.OwnerReferences) != 1 {
		t.Fatalf("expected 1 ownerReference, got %d", len(got.OwnerReferences))
	}
	or := got.OwnerReferences[0]
	if or.Kind != v1alpha1.KindRole || or.Name != "istiod" || or.UID != "istiod-uid" {
		t.Errorf("ownerRef = %+v, want Kind/Name/UID matching the source role", or)
	}
	if or.Controller == nil || !*or.Controller {
		t.Errorf("ownerRef.Controller must be true for GC")
	}
}

// TestRoleReconciler_UpdatesExistingReport reconciles twice with a changed
// rule set in between, and confirms the second reconcile updates (not
// creates) the report.
func TestRoleReconciler_UpdatesExistingReport(t *testing.T) {
	ctx := context.Background()
	role := istiodRole()
	policy := ksv049Policy()
	c := newClient(t, role, policy)

	r := &RoleReconciler{Client: c}
	reconcileRole(ctx, t, r, role)

	// Drop the violating verb so the second reconcile produces a clean report.
	role.Rules[0].Verbs = []string{"get", "list"}
	if err := c.Update(ctx, role); err != nil {
		t.Fatalf("update Role: %v", err)
	}
	reconcileRole(ctx, t, r, role)

	var got v1alpha1.RbacReport
	if err := c.Get(ctx, types.NamespacedName{Namespace: "istio-system", Name: "istiod"}, &got); err != nil {
		t.Fatalf("get report: %v", err)
	}
	if len(got.Report.Checks) != 0 {
		t.Errorf("expected 0 checks after rule change, got %d", len(got.Report.Checks))
	}
	if got.Report.Summary.TotalCount != 0 {
		t.Errorf("expected zero totals, got %+v", got.Report.Summary)
	}
}

// TestRoleReconciler_DeletedRoleIsNoOp confirms that a Reconcile call for a
// non-existent Role returns nil error and does not create a report. (Real
// deletion goes through GC via ownerReference.)
func TestRoleReconciler_DeletedRoleIsNoOp(t *testing.T) {
	ctx := context.Background()
	c := newClient(t /* no role, no policy */)

	r := &RoleReconciler{Client: c}
	res, err := r.Reconcile(ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: "ns", Name: "missing"},
	})
	if err != nil {
		t.Fatalf("expected nil error for missing role, got %v", err)
	}
	if res != (ctrl.Result{}) {
		t.Errorf("expected empty Result, got %+v", res)
	}

	// No report should have been created.
	var list v1alpha1.RbacReportList
	if err := c.List(ctx, &list); err != nil {
		t.Fatalf("list reports: %v", err)
	}
	if len(list.Items) != 0 {
		t.Errorf("expected 0 reports, got %d", len(list.Items))
	}
}

// TestRoleReconciler_NoPoliciesProducesEmptyReport confirms a role with
// no matching policies still gets a report with empty checks.
func TestRoleReconciler_NoPoliciesProducesEmptyReport(t *testing.T) {
	ctx := context.Background()
	role := istiodRole()
	c := newClient(t, role) // no policies in cluster

	r := &RoleReconciler{Client: c}
	reconcileRole(ctx, t, r, role)

	var got v1alpha1.RbacReport
	if err := c.Get(ctx, types.NamespacedName{Namespace: "istio-system", Name: "istiod"}, &got); err != nil {
		t.Fatalf("get report: %v", err)
	}
	if got.Report.Checks == nil {
		t.Errorf("Checks must be empty slice (not nil) for clean role")
	}
	if len(got.Report.Checks) != 0 {
		t.Errorf("expected 0 checks, got %d", len(got.Report.Checks))
	}
}

// TestRoleReconciler_ReportNameIsSafe confirms a colon-bearing role name
// is sanitized in metadata.name while the original is preserved in roleRef.
func TestRoleReconciler_ReportNameIsSafe(t *testing.T) {
	ctx := context.Background()
	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "system:auth-reader",
			Namespace: "kube-system",
			UID:       "u",
		},
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{""},
			Resources: []string{"configmaps"},
			Verbs:     []string{"create"},
		}},
	}
	c := newClient(t, role, ksv049Policy())

	r := &RoleReconciler{Client: c}
	reconcileRole(ctx, t, r, role)

	var got v1alpha1.RbacReport
	// Name in the apiserver = safe form
	if err := c.Get(ctx, types.NamespacedName{Namespace: "kube-system", Name: "system-auth-reader"}, &got); err != nil {
		t.Fatalf("get report by safe name: %v", err)
	}
	if got.Spec.RoleRef.Name != "system:auth-reader" {
		t.Errorf("roleRef.Name = %q, want original colon form", got.Spec.RoleRef.Name)
	}
}

// TestEnqueueAllRoles_FanOut exercises the policy-fan-out helper directly:
// given three Role objects in the client, the helper must produce three
// reconcile.Request entries.
func TestEnqueueAllRoles_FanOut(t *testing.T) {
	ctx := context.Background()
	roles := []client.Object{
		&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Namespace: "ns1", Name: "a"}},
		&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Namespace: "ns1", Name: "b"}},
		&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Namespace: "ns2", Name: "c"}},
	}
	c := newClient(t, roles...)

	got := enqueueAllRoles(ctx, c)
	if len(got) != 3 {
		t.Fatalf("got %d requests, want 3", len(got))
	}

	// Build a set so order doesn't matter.
	want := map[string]bool{
		"ns1/a": true, "ns1/b": true, "ns2/c": true,
	}
	for _, req := range got {
		key := req.Namespace + "/" + req.Name
		if !want[key] {
			t.Errorf("unexpected request key %q", key)
		}
		delete(want, key)
	}
	if len(want) != 0 {
		t.Errorf("missing requests: %v", want)
	}
}

// TestEnqueueAllRoles_EmptyCluster confirms the helper returns an empty
// slice (not nil) when no roles exist, so the controller-runtime workqueue
// receives nothing rather than logging a confusing nil dereference.
func TestEnqueueAllRoles_EmptyCluster(t *testing.T) {
	c := newClient(t)
	got := enqueueAllRoles(context.Background(), c)
	if len(got) != 0 {
		t.Errorf("expected 0 requests, got %d", len(got))
	}
}

// TestRoleReconciler_PolicyFanOutClosure smoke-tests the closure that the
// SetupWithManager wiring would call. It must produce one request per
// existing Role regardless of which policy object is passed in.
func TestRoleReconciler_PolicyFanOutClosure(t *testing.T) {
	role := istiodRole()
	c := newClient(t, role)

	r := &RoleReconciler{Client: c}
	got := r.policyFanOut(context.Background(), ksv049Policy())

	if len(got) != 1 {
		t.Fatalf("expected 1 request, got %d", len(got))
	}
	want := reconcile.Request{NamespacedName: types.NamespacedName{Namespace: "istio-system", Name: "istiod"}}
	if got[0] != want {
		t.Errorf("got %+v, want %+v", got[0], want)
	}
}
