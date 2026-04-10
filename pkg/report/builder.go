// Package report builds RbacReport and ClusterRbacReport objects from
// policy-engine findings.
package report

import (
	"sort"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s-rbac-engine/pkg/apis/rbacreports/v1alpha1"
	"k8s-rbac-engine/pkg/indexer"
	"k8s-rbac-engine/pkg/policyengine"
)

// Scanner identification embedded into every report.
const (
	ScannerName    = "rbac-reports-operator"
	ScannerVendor  = "PRO-Robotech"
	ScannerVersion = "0.3.0"
)

// Label keys applied to every report.
const (
	LabelResourceKind  = "rbac-reports.io/resource-kind"
	LabelManagedBy     = "app.kubernetes.io/managed-by"
	LabelManagedByName = "rbac-reports-operator"
)

// API metadata for the rbacreports.in-cloud.io group.
const (
	APIVersion        = "rbacreports.in-cloud.io/v1alpha1"
	KindRbacReport    = "RbacReport"
	KindClusterReport = "ClusterRbacReport"

	roleAPIVersion = "rbac.authorization.k8s.io/v1"
)

// SafeName converts a Role/ClusterRole name into a value valid for metadata.name
// by replacing ":" with "-".
func SafeName(roleName string) string {
	return strings.ReplaceAll(roleName, ":", "-")
}

// BuildRbacReport constructs an RbacReport for a Role.
func BuildRbacReport(role *indexer.RoleRecord, findings []policyengine.Finding) *v1alpha1.RbacReport {
	return &v1alpha1.RbacReport{
		TypeMeta: metav1.TypeMeta{
			APIVersion: APIVersion,
			Kind:       KindRbacReport,
		},
		ObjectMeta: buildObjectMeta(role, v1alpha1.KindRole),
		Spec: v1alpha1.ReportSpec{
			RoleRef: buildRoleRef(role),
			Scanner: defaultScanner(),
		},
		Report: buildReport(findings),
	}
}

// BuildClusterRbacReport constructs a ClusterRbacReport for a ClusterRole.
func BuildClusterRbacReport(role *indexer.RoleRecord, findings []policyengine.Finding) *v1alpha1.ClusterRbacReport {
	meta := buildObjectMeta(role, v1alpha1.KindClusterRole)
	meta.Namespace = ""

	return &v1alpha1.ClusterRbacReport{
		TypeMeta: metav1.TypeMeta{
			APIVersion: APIVersion,
			Kind:       KindClusterReport,
		},
		ObjectMeta: meta,
		Spec: v1alpha1.ReportSpec{
			RoleRef: buildRoleRef(role),
			Scanner: defaultScanner(),
		},
		Report: buildReport(findings),
	}
}

func buildObjectMeta(role *indexer.RoleRecord, resourceKind string) metav1.ObjectMeta {
	controller := true
	blockOwnerDeletion := false

	return metav1.ObjectMeta{
		Name:      SafeName(role.Name),
		Namespace: role.Namespace,
		Labels: map[string]string{
			LabelResourceKind: resourceKind,
			LabelManagedBy:    LabelManagedByName,
		},
		OwnerReferences: []metav1.OwnerReference{
			{
				APIVersion:         roleAPIVersion,
				Kind:               resourceKind,
				Name:               role.Name,
				UID:                role.UID,
				Controller:         &controller,
				BlockOwnerDeletion: &blockOwnerDeletion,
			},
		},
	}
}

func buildRoleRef(role *indexer.RoleRecord) v1alpha1.RoleRef {
	return v1alpha1.RoleRef{
		Kind:      role.Kind,
		Name:      role.Name,
		Namespace: role.Namespace,
		UID:       role.UID,
	}
}

func defaultScanner() v1alpha1.Scanner {
	return v1alpha1.Scanner{
		Name:    ScannerName,
		Vendor:  ScannerVendor,
		Version: ScannerVersion,
	}
}

// buildReport coalesces findings by CheckID and computes the summary.
// Report.Checks is always a non-nil slice (empty for clean roles).
func buildReport(findings []policyengine.Finding) v1alpha1.Report {
	checks := coalesceFindings(findings)
	sortChecks(checks)

	return v1alpha1.Report{
		Checks:  checks,
		Summary: buildSummary(checks),
	}
}

// coalesceFindings groups findings by CheckID into Check entries with multiple Messages.
func coalesceFindings(findings []policyengine.Finding) []v1alpha1.Check {
	// non-nil so JSON marshals as "checks: []" not "checks: null"
	checks := make([]v1alpha1.Check, 0)
	if len(findings) == 0 {
		return checks
	}

	byCheckID := make(map[string]int)
	for i := range findings {
		f := &findings[i]
		idx, ok := byCheckID[f.Policy.Spec.CheckID]
		if !ok {
			checks = append(checks, v1alpha1.Check{
				CheckID:     f.Policy.Spec.CheckID,
				Category:    f.Policy.Spec.Category,
				Severity:    f.Policy.Spec.Severity,
				Title:       f.Policy.Spec.Title,
				Description: f.Policy.Spec.Description,
				Remediation: f.Policy.Spec.Remediation,
				Messages:    []string{f.Message},
				Success:     false,
			})
			byCheckID[f.Policy.Spec.CheckID] = len(checks) - 1

			continue
		}
		checks[idx].Messages = append(checks[idx].Messages, f.Message)
	}

	return checks
}

// sortChecks orders checks by severity (highest first), then CheckID alphabetically.
func sortChecks(checks []v1alpha1.Check) {
	sort.SliceStable(checks, func(i, j int) bool {
		if pi, pj := severitySortKey(checks[i].Severity), severitySortKey(checks[j].Severity); pi != pj {
			return pi < pj
		}

		return checks[i].CheckID < checks[j].CheckID
	})
}

func severitySortKey(s v1alpha1.Severity) int {
	if rank, ok := s.Priority(); ok {
		return rank
	}

	return unknownSeveritySortKey
}

const unknownSeveritySortKey = 1 << 30

// buildSummary aggregates per-severity counts and sets TotalCount.
func buildSummary(checks []v1alpha1.Check) v1alpha1.Summary {
	var s v1alpha1.Summary
	for i := range checks {
		switch checks[i].Severity {
		case v1alpha1.SeverityCritical:
			s.CriticalCount++
		case v1alpha1.SeverityHigh:
			s.HighCount++
		case v1alpha1.SeverityMedium:
			s.MediumCount++
		case v1alpha1.SeverityLow:
			s.LowCount++
		}
	}
	s.TotalCount = s.CriticalCount + s.HighCount + s.MediumCount + s.LowCount

	return s
}
