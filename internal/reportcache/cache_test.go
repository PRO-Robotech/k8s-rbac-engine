package reportcache

import (
	"errors"
	"fmt"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	api "k8s-rbac-engine/pkg/apis/rbacgraph"
	rrv1 "k8s-rbac-engine/pkg/apis/rbacreports/v1alpha1"
)

// newTestCache returns a Cache with a populated entries map but no real
// informer attached. Sufficient for testing the lookup, set, delete, and
// event-handler conversion paths in isolation.
//
// Integration with the controller-runtime cache (informer wiring,
// list-watch, sync) is exercised at the start.go level — verifying it
// here would require envtest, which is not justified for this small
// surface.
func newTestCache() *Cache {
	return &Cache{
		byKind: make(map[lookupKey]*api.Assessment),
	}
}

// TestCache_Lookup_NilSafety covers the engine.ReportLookup contract.
func TestCache_Lookup_NilSafety(t *testing.T) {
	c := newTestCache()
	if got := c.Lookup(rrv1.KindRole, "ns", "missing"); got != nil {
		t.Errorf("empty cache must return nil, got %+v", got)
	}
}

// TestCache_OnRbacReport stores and retrieves a namespaced report.
func TestCache_OnRbacReport(t *testing.T) {
	c := newTestCache()
	report := &rrv1.RbacReport{
		ObjectMeta: metav1.ObjectMeta{Name: "istiod", Namespace: "istio-system"},
		Spec: rrv1.ReportSpec{
			RoleRef: rrv1.RoleRef{
				Kind:      rrv1.KindRole,
				Name:      "istiod",
				Namespace: "istio-system",
			},
		},
		Report: rrv1.Report{
			Summary: rrv1.Summary{MediumCount: 1, TotalCount: 1},
			Checks: []rrv1.Check{
				{CheckID: "KSV049", Severity: rrv1.SeverityMedium},
			},
		},
	}

	c.onRbacReport(report)

	got := c.Lookup(rrv1.KindRole, "istio-system", "istiod")
	if got == nil {
		t.Fatalf("expected assessment for istiod, got nil")
	}
	if got.HighestSeverity != "MEDIUM" || got.TotalCount != 1 {
		t.Errorf("assessment = %+v, want HighestSeverity=MEDIUM total=1", got)
	}
}

// TestCache_OnClusterRbacReport stores and retrieves a cluster-scoped report.
func TestCache_OnClusterRbacReport(t *testing.T) {
	c := newTestCache()
	report := &rrv1.ClusterRbacReport{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster-admin"},
		Spec: rrv1.ReportSpec{
			RoleRef: rrv1.RoleRef{
				Kind: rrv1.KindClusterRole,
				Name: "cluster-admin",
			},
		},
		Report: rrv1.Report{
			Summary: rrv1.Summary{CriticalCount: 1, TotalCount: 1},
			Checks: []rrv1.Check{
				{CheckID: "KSV044", Severity: rrv1.SeverityCritical},
			},
		},
	}

	c.onClusterRbacReport(report)

	// ClusterRbacReport key has empty namespace.
	got := c.Lookup(rrv1.KindClusterRole, "", "cluster-admin")
	if got == nil {
		t.Fatalf("expected assessment for cluster-admin, got nil")
	}
	if got.HighestSeverity != "CRITICAL" {
		t.Errorf("HighestSeverity = %q, want CRITICAL", got.HighestSeverity)
	}
}

// TestCache_OnRbacReport_PreservesColonName confirms that
// resolveRoleIdentity prefers spec.roleRef.name (the original colon-form)
// over metadata.name (the safe form) — the lookup uses the original form
// because that's what pkg/indexer keys roles by.
func TestCache_OnRbacReport_PreservesColonName(t *testing.T) {
	c := newTestCache()
	report := &rrv1.ClusterRbacReport{
		// Safe form in metadata.name.
		ObjectMeta: metav1.ObjectMeta{Name: "system-auth-delegator"},
		Spec: rrv1.ReportSpec{
			RoleRef: rrv1.RoleRef{
				Kind: rrv1.KindClusterRole,
				// Original colon-form in spec.roleRef.name.
				Name: "system:auth-delegator",
			},
		},
		Report: rrv1.Report{Summary: rrv1.Summary{HighCount: 1, TotalCount: 1}},
	}

	c.onClusterRbacReport(report)

	if got := c.Lookup(rrv1.KindClusterRole, "", "system:auth-delegator"); got == nil {
		t.Errorf("lookup by colon-form name should hit, got nil")
	}
	if got := c.Lookup(rrv1.KindClusterRole, "", "system-auth-delegator"); got != nil {
		t.Errorf("lookup by safe-form name should miss; got %+v", got)
	}
}

// TestCache_DeleteRemovesEntry verifies the Delete event handler.
func TestCache_DeleteRemovesEntry(t *testing.T) {
	c := newTestCache()
	report := &rrv1.RbacReport{
		ObjectMeta: metav1.ObjectMeta{Name: "x", Namespace: "ns"},
		Spec: rrv1.ReportSpec{RoleRef: rrv1.RoleRef{
			Kind:      rrv1.KindRole,
			Name:      "x",
			Namespace: "ns",
		}},
		Report: rrv1.Report{Summary: rrv1.Summary{LowCount: 1, TotalCount: 1}},
	}
	c.onRbacReport(report)
	if c.Lookup(rrv1.KindRole, "ns", "x") == nil {
		t.Fatalf("setup: expected entry after onRbacReport")
	}

	c.onRbacReportDelete(report)

	if got := c.Lookup(rrv1.KindRole, "ns", "x"); got != nil {
		t.Errorf("entry should be deleted, still got %+v", got)
	}
}

// TestCache_OnRbacReport_NilReportNoOp guards against panics if an
// informer ever delivers a nil object (defensive — informers shouldn't,
// but the cost of the check is one comparison).
func TestCache_OnRbacReport_NilReportNoOp(t *testing.T) {
	c := newTestCache()
	c.onRbacReport(nil)
	c.onRbacReport((*rrv1.RbacReport)(nil))
	c.onClusterRbacReport(nil)
	c.onClusterRbacReport((*rrv1.ClusterRbacReport)(nil))
	// No panic = pass. Cache still empty.
	if len(c.byKind) != 0 {
		t.Errorf("nil events should not populate cache, got %d entries", len(c.byKind))
	}
}

// TestCache_Snapshot returns a stable view for tests.
func TestCache_Snapshot(t *testing.T) {
	c := newTestCache()
	c.onRbacReport(&rrv1.RbacReport{
		Spec: rrv1.ReportSpec{RoleRef: rrv1.RoleRef{
			Kind: rrv1.KindRole, Name: "a", Namespace: "ns1",
		}},
		Report: rrv1.Report{Summary: rrv1.Summary{HighCount: 1, TotalCount: 1}},
	})
	c.onClusterRbacReport(&rrv1.ClusterRbacReport{
		Spec: rrv1.ReportSpec{RoleRef: rrv1.RoleRef{
			Kind: rrv1.KindClusterRole, Name: "view",
		}},
		Report: rrv1.Report{Summary: rrv1.Summary{LowCount: 1, TotalCount: 1}},
	})

	snap := c.Snapshot()
	if len(snap) != 2 {
		t.Fatalf("snapshot len = %d, want 2", len(snap))
	}
	if _, ok := snap["Role/ns1/a"]; !ok {
		t.Errorf("missing Role/ns1/a in snapshot: %v", snap)
	}
	if _, ok := snap["ClusterRole//view"]; !ok {
		t.Errorf("missing ClusterRole//view in snapshot: %v", snap)
	}
}

// TestErrCRDNotInstalled_Sentinel makes sure the public sentinel is the
// one callers can match with errors.Is() even after wrapping.
func TestErrCRDNotInstalled_Sentinel(t *testing.T) {
	if ErrCRDNotInstalled == nil {
		t.Fatal("ErrCRDNotInstalled must not be nil")
	}
	wrapped := fmt.Errorf("wrapped: %w", ErrCRDNotInstalled)
	if !errors.Is(wrapped, ErrCRDNotInstalled) {
		t.Errorf("wrapped sentinel must satisfy errors.Is")
	}
}
