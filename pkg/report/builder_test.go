package report

import (
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/types"

	"k8s-rbac-engine/pkg/apis/rbacreports/v1alpha1"
	"k8s-rbac-engine/pkg/indexer"
	"k8s-rbac-engine/pkg/policyengine"
)

// TestSafeName covers the RFC 1123 sanitization rule from the report
// builder contract.
func TestSafeName(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"istiod", "istiod"},
		{"system:controller:bootstrap-signer", "system-controller-bootstrap-signer"},
		{"system:auth-delegator", "system-auth-delegator"},
		{"", ""},
		{"::", "--"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := SafeName(tt.in); got != tt.want {
				t.Fatalf("SafeName(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// helper: build a finding for the given (checkID, severity, message).
func mkFinding(checkID string, severity v1alpha1.Severity, message string) policyengine.Finding {
	return policyengine.Finding{
		Policy: &v1alpha1.RbacPolicy{
			Spec: v1alpha1.RbacPolicySpec{
				CheckID:     checkID,
				Severity:    severity,
				Category:    "Kubernetes Security Check",
				Title:       checkID + " title",
				Description: checkID + " description",
				Remediation: checkID + " remediation",
			},
		},
		Message: message,
	}
}

// TestBuildRbacReport_CleanRole exercises the empty-findings path and
// verifies that checks is an empty slice, not nil.
func TestBuildRbacReport_CleanRole(t *testing.T) {
	role := &indexer.RoleRecord{
		UID: "role-uid", Kind: v1alpha1.KindRole,
		Namespace: "ns", Name: "clean",
	}
	r := BuildRbacReport(role, nil)

	if r.Report.Checks == nil {
		t.Errorf("Checks must be empty slice, not nil")
	}
	if len(r.Report.Checks) != 0 {
		t.Errorf("expected 0 checks, got %d", len(r.Report.Checks))
	}
	if want := (v1alpha1.Summary{}); r.Report.Summary != want {
		t.Errorf("Summary = %+v, want zero", r.Report.Summary)
	}
	if r.Name != "clean" {
		t.Errorf("Name = %q, want clean", r.Name)
	}
	if r.Namespace != "ns" {
		t.Errorf("Namespace = %q, want ns", r.Namespace)
	}
}

// TestBuildRbacReport_OwnerReferenceAndLabels checks owner refs and labels.
func TestBuildRbacReport_OwnerReferenceAndLabels(t *testing.T) {
	role := &indexer.RoleRecord{
		UID: types.UID("role-uid-123"), Kind: v1alpha1.KindRole,
		Namespace: "istio-system", Name: "istiod",
	}
	r := BuildRbacReport(role, nil)

	if got := r.Labels[LabelResourceKind]; got != v1alpha1.KindRole {
		t.Errorf("label %s = %q, want %q", LabelResourceKind, got, v1alpha1.KindRole)
	}
	if got := r.Labels[LabelManagedBy]; got != LabelManagedByName {
		t.Errorf("label %s = %q, want %q", LabelManagedBy, got, LabelManagedByName)
	}

	if len(r.OwnerReferences) != 1 {
		t.Fatalf("expected 1 ownerReference, got %d", len(r.OwnerReferences))
	}
	or := r.OwnerReferences[0]
	if or.APIVersion != "rbac.authorization.k8s.io/v1" {
		t.Errorf("ownerRef APIVersion = %q", or.APIVersion)
	}
	if or.Kind != v1alpha1.KindRole {
		t.Errorf("ownerRef Kind = %q", or.Kind)
	}
	if or.Name != "istiod" {
		t.Errorf("ownerRef Name = %q, want istiod (original name preserved)", or.Name)
	}
	if or.UID != "role-uid-123" {
		t.Errorf("ownerRef UID = %q", or.UID)
	}
	if or.Controller == nil || !*or.Controller {
		t.Errorf("ownerRef Controller must be true")
	}
}

// TestBuildRbacReport_RoleRefPreservesOriginalName confirms metadata.name
// uses the safe form while spec.roleRef.name preserves the colon-bearing original.
func TestBuildRbacReport_RoleRefPreservesOriginalName(t *testing.T) {
	role := &indexer.RoleRecord{
		UID: "uid", Kind: v1alpha1.KindClusterRole,
		Name: "system:controller:bootstrap-signer",
	}
	r := BuildClusterRbacReport(role, nil)

	if r.Name != "system-controller-bootstrap-signer" {
		t.Errorf("metadata.name = %q, want safe form", r.Name)
	}
	if r.Spec.RoleRef.Name != "system:controller:bootstrap-signer" {
		t.Errorf("spec.roleRef.name = %q, want original colon-form", r.Spec.RoleRef.Name)
	}
}

// TestBuildClusterRbacReport_ClusterScoped confirms the namespace is empty
// even if role.Namespace is set (defensive — ClusterRole has no namespace
// but the helper should not propagate one if it leaks in).
func TestBuildClusterRbacReport_ClusterScoped(t *testing.T) {
	role := &indexer.RoleRecord{
		UID: "uid", Kind: v1alpha1.KindClusterRole,
		Namespace: "leaked-ns", // intentionally wrong
		Name:      "cluster-admin",
	}
	r := BuildClusterRbacReport(role, nil)

	if r.Namespace != "" {
		t.Errorf("ClusterRbacReport must be cluster-scoped, got namespace %q", r.Namespace)
	}
	if r.Kind != KindClusterReport {
		t.Errorf("Kind = %q, want %q", r.Kind, KindClusterReport)
	}
	if r.OwnerReferences[0].Kind != v1alpha1.KindClusterRole {
		t.Errorf("ownerRef Kind = %q, want ClusterRole", r.OwnerReferences[0].Kind)
	}
}

// TestBuildReport_CoalesceFindings checks that multiple findings with the
// same CheckID become a single Check with multiple Messages.
func TestBuildReport_CoalesceFindings(t *testing.T) {
	role := &indexer.RoleRecord{
		UID: "uid", Kind: v1alpha1.KindRole, Namespace: "ns", Name: "multi",
	}
	findings := []policyengine.Finding{
		mkFinding("KSV049", v1alpha1.SeverityMedium, "msg-1"),
		mkFinding("KSV050", v1alpha1.SeverityCritical, "msg-2"),
		mkFinding("KSV049", v1alpha1.SeverityMedium, "msg-3"),
	}
	r := BuildRbacReport(role, findings)

	if len(r.Report.Checks) != 2 {
		t.Fatalf("expected 2 checks (KSV049 + KSV050), got %d", len(r.Report.Checks))
	}

	// After sorting by severity, KSV050 (CRITICAL) comes before KSV049 (MEDIUM).
	if r.Report.Checks[0].CheckID != "KSV050" {
		t.Errorf("Checks[0] = %q, want KSV050 (CRITICAL sorts first)", r.Report.Checks[0].CheckID)
	}
	if r.Report.Checks[1].CheckID != "KSV049" {
		t.Errorf("Checks[1] = %q, want KSV049", r.Report.Checks[1].CheckID)
	}

	// KSV049 should have two messages, in order.
	ksv049 := r.Report.Checks[1]
	if len(ksv049.Messages) != 2 {
		t.Fatalf("KSV049 messages = %d, want 2", len(ksv049.Messages))
	}
	if ksv049.Messages[0] != "msg-1" || ksv049.Messages[1] != "msg-3" {
		t.Errorf("KSV049 messages = %v, want [msg-1 msg-3] (insertion order)", ksv049.Messages)
	}

	// All checks have success: false (only violations are reported).
	for _, c := range r.Report.Checks {
		if c.Success {
			t.Errorf("check %s has success=true; only violations should be reported", c.CheckID)
		}
	}
}

// TestBuildReport_SummaryCounts verifies summary aggregation across all
// four severity buckets and that TotalCount is the sum.
func TestBuildReport_SummaryCounts(t *testing.T) {
	role := &indexer.RoleRecord{Kind: v1alpha1.KindRole, Name: "x"}
	findings := []policyengine.Finding{
		mkFinding("C1", v1alpha1.SeverityCritical, "m"),
		mkFinding("C2", v1alpha1.SeverityCritical, "m"),
		mkFinding("H1", v1alpha1.SeverityHigh, "m"),
		mkFinding("M1", v1alpha1.SeverityMedium, "m"),
		mkFinding("M2", v1alpha1.SeverityMedium, "m"),
		mkFinding("M3", v1alpha1.SeverityMedium, "m"),
		mkFinding("L1", v1alpha1.SeverityLow, "m"),
	}
	s := BuildRbacReport(role, findings).Report.Summary

	if s.CriticalCount != 2 {
		t.Errorf("CriticalCount = %d, want 2", s.CriticalCount)
	}
	if s.HighCount != 1 {
		t.Errorf("HighCount = %d, want 1", s.HighCount)
	}
	if s.MediumCount != 3 {
		t.Errorf("MediumCount = %d, want 3", s.MediumCount)
	}
	if s.LowCount != 1 {
		t.Errorf("LowCount = %d, want 1", s.LowCount)
	}
	if s.TotalCount != 7 {
		t.Errorf("TotalCount = %d, want 7", s.TotalCount)
	}
	wantSum := s.CriticalCount + s.HighCount + s.MediumCount + s.LowCount
	if s.TotalCount != wantSum {
		t.Errorf("TotalCount = %d, sum of severities = %d (must equal)", s.TotalCount, wantSum)
	}
}

// TestSortChecks_DeterministicOrder confirms checks of the same severity
// are tiebroken by CheckID alphabetically.
func TestSortChecks_DeterministicOrder(t *testing.T) {
	role := &indexer.RoleRecord{Kind: v1alpha1.KindRole, Name: "x"}
	findings := []policyengine.Finding{
		mkFinding("KSV050", v1alpha1.SeverityCritical, "m"),
		mkFinding("KSV041", v1alpha1.SeverityCritical, "m"),
		mkFinding("KSV049", v1alpha1.SeverityMedium, "m"),
	}
	r := BuildRbacReport(role, findings)

	want := []string{"KSV041", "KSV050", "KSV049"} // critical (alpha) then medium
	for i, c := range r.Report.Checks {
		if c.CheckID != want[i] {
			t.Errorf("Checks[%d] = %s, want %s", i, c.CheckID, want[i])
		}
	}
}

// TestBuildReport_EndToEnd_SpecExample chains policyengine + report builder
// against a canonical violating role and pins the resulting report shape.
func TestBuildReport_EndToEnd_SpecExample(t *testing.T) {
	role := &indexer.RoleRecord{
		UID: "istiod-uid", Kind: v1alpha1.KindRole,
		Namespace: "istio-system", Name: "istiod",
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{""},
			Resources: []string{"configmaps"},
			Verbs:     []string{"create", "update"},
		}},
	}
	policies := []v1alpha1.RbacPolicy{
		{
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
		},
	}

	findings := policyengine.Evaluate(role, policies)
	r := BuildRbacReport(role, findings)

	// metadata
	if r.Name != "istiod" {
		t.Errorf("metadata.name = %q, want istiod", r.Name)
	}
	if r.Namespace != "istio-system" {
		t.Errorf("metadata.namespace = %q", r.Namespace)
	}

	// spec.roleRef
	if r.Spec.RoleRef.Kind != v1alpha1.KindRole {
		t.Errorf("roleRef.Kind = %q", r.Spec.RoleRef.Kind)
	}
	if r.Spec.RoleRef.Name != "istiod" {
		t.Errorf("roleRef.Name = %q", r.Spec.RoleRef.Name)
	}
	if r.Spec.RoleRef.UID != "istiod-uid" {
		t.Errorf("roleRef.UID = %q", r.Spec.RoleRef.UID)
	}

	// spec.scanner
	if r.Spec.Scanner.Name != ScannerName || r.Spec.Scanner.Vendor != ScannerVendor {
		t.Errorf("scanner = %+v", r.Spec.Scanner)
	}

	// report.checks
	if len(r.Report.Checks) != 1 {
		t.Fatalf("expected 1 check, got %d", len(r.Report.Checks))
	}
	c := r.Report.Checks[0]
	if c.CheckID != "KSV049" {
		t.Errorf("CheckID = %q", c.CheckID)
	}
	if c.Severity != v1alpha1.SeverityMedium {
		t.Errorf("Severity = %q", c.Severity)
	}
	if c.Success {
		t.Errorf("Success must be false")
	}
	if len(c.Messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(c.Messages))
	}
	wantMsg := "Role 'istiod' should not have access to resource 'configmaps' for verbs [create, update] in namespace 'istio-system'"
	if c.Messages[0] != wantMsg {
		t.Errorf("Message = %q\nwant     %q", c.Messages[0], wantMsg)
	}

	// summary
	want := v1alpha1.Summary{MediumCount: 1, TotalCount: 1}
	if r.Report.Summary != want {
		t.Errorf("Summary = %+v, want %+v", r.Report.Summary, want)
	}
}

// TestBuildReport_TypeMetaFields confirms apiVersion and kind are set so
// the controller can post the object to the apiserver without further
// scaffolding.
func TestBuildReport_TypeMetaFields(t *testing.T) {
	role := &indexer.RoleRecord{Kind: v1alpha1.KindRole, Name: "x"}

	r := BuildRbacReport(role, nil)
	if r.APIVersion != APIVersion {
		t.Errorf("RbacReport APIVersion = %q", r.APIVersion)
	}
	if r.Kind != KindRbacReport {
		t.Errorf("RbacReport Kind = %q", r.Kind)
	}

	cr := BuildClusterRbacReport(&indexer.RoleRecord{Kind: v1alpha1.KindClusterRole, Name: "x"}, nil)
	if cr.APIVersion != APIVersion {
		t.Errorf("ClusterRbacReport APIVersion = %q", cr.APIVersion)
	}
	if cr.Kind != KindClusterReport {
		t.Errorf("ClusterRbacReport Kind = %q", cr.Kind)
	}
}
