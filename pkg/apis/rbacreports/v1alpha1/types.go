// Package v1alpha1 contains Go types for the rbacreports.incloud.io/v1alpha1 API
// group: RbacPolicy, RbacReport, and ClusterRbacReport.
package v1alpha1

import (
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"k8s-rbac-engine/pkg/conditions"
)

// Severity classifies the impact of a policy violation.
//
// +kubebuilder:validation:Enum=CRITICAL;HIGH;MEDIUM;LOW
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
)

var severityRanks = map[Severity]int{
	SeverityCritical: 0,
	SeverityHigh:     1,
	SeverityMedium:   2,
	SeverityLow:      3,
}

func (s Severity) Priority() (int, bool) {
	rank, ok := severityRanks[s]

	return rank, ok
}

func ParseSeverity(s string) Severity {
	candidate := Severity(strings.ToUpper(strings.TrimSpace(s)))
	if _, ok := severityRanks[candidate]; ok {
		return candidate
	}

	return ""
}

// MatchMode controls how "*" is interpreted during policy matching.
//
// +kubebuilder:validation:Enum=wildcard;exact
type MatchMode string

const (
	// MatchModeWildcard treats "*" on either side as a wildcard. This is
	// the default and is used to find roles with dangerous permissions.
	MatchModeWildcard MatchMode = "wildcard"
	// MatchModeExact treats "*" as a literal string. Used to find roles
	// that contain a literal wildcard token (e.g., KSV044).
	MatchModeExact MatchMode = "exact"
)

// Resource kind constants used in TargetKinds and report labels.
const (
	KindRole        = "Role"
	KindClusterRole = "ClusterRole"
)

// RbacPolicy is a cluster-scoped declarative security policy.
//
// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster,shortName=rp
type RbacPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec RbacPolicySpec `json:"spec"`
}

// RbacPolicyList is the List type for RbacPolicy.
//
// +kubebuilder:object:root=true
type RbacPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []RbacPolicy `json:"items"`
}

// RbacPolicySpec is the user-authored specification of an RbacPolicy.
type RbacPolicySpec struct {
	Severity    Severity `json:"severity"`
	Category    string   `json:"category"`
	CheckID     string   `json:"checkID"`
	Title       string   `json:"title"`
	Description string   `json:"description,omitempty"`
	Remediation string   `json:"remediation,omitempty"`

	// TargetKinds restricts the policy to specific role kinds. Empty means
	// the policy applies to both Role and ClusterRole.
	TargetKinds []string `json:"targetKinds,omitempty"`

	Match   Match   `json:"match"`
	Exclude Exclude `json:"exclude,omitempty"`
}

type Match struct {
	MatchMode  MatchMode              `json:"matchMode,omitempty"`
	Resources  []string               `json:"resources,omitempty"`
	Verbs      []string               `json:"verbs,omitempty"`
	APIGroups  []string               `json:"apiGroups,omitempty"`
	Conditions []conditions.Condition `json:"conditions,omitempty"`
}

type Exclude struct {
	Namespaces []string `json:"namespaces,omitempty"`
	RoleNames  []string `json:"roleNames,omitempty"`
}

// RbacReport - ...
//
// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Namespaced,shortName=rr
// +kubebuilder:printcolumn:name="Role",type="string",JSONPath=".spec.roleRef.name"
// +kubebuilder:printcolumn:name="Critical",type="integer",JSONPath=".report.summary.criticalCount"
// +kubebuilder:printcolumn:name="High",type="integer",JSONPath=".report.summary.highCount"
// +kubebuilder:printcolumn:name="Medium",type="integer",JSONPath=".report.summary.mediumCount"
// +kubebuilder:printcolumn:name="Low",type="integer",JSONPath=".report.summary.lowCount"
type RbacReport struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ReportSpec `json:"spec"`
	Report Report     `json:"report"`
}

// ClusterRbacReport - ...
//
// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster,shortName=crr
// +kubebuilder:printcolumn:name="ClusterRole",type="string",JSONPath=".spec.roleRef.name"
// +kubebuilder:printcolumn:name="Critical",type="integer",JSONPath=".report.summary.criticalCount"
// +kubebuilder:printcolumn:name="High",type="integer",JSONPath=".report.summary.highCount"
// +kubebuilder:printcolumn:name="Medium",type="integer",JSONPath=".report.summary.mediumCount"
// +kubebuilder:printcolumn:name="Low",type="integer",JSONPath=".report.summary.lowCount"
type ClusterRbacReport struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ReportSpec `json:"spec"`
	Report Report     `json:"report"`
}

// RbacReportList is the List type for RbacReport.
//
// +kubebuilder:object:root=true
type RbacReportList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []RbacReport `json:"items"`
}

// ClusterRbacReportList is the List type for ClusterRbacReport.
//
// +kubebuilder:object:root=true
type ClusterRbacReportList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []ClusterRbacReport `json:"items"`
}

// ReportSpec carries the back-pointer to the audited role and the scanner
// metadata block (Trivy-compatible).
type ReportSpec struct {
	RoleRef RoleRef `json:"roleRef"`
	Scanner Scanner `json:"scanner"`
}

// RoleRef identifies the audited Role/ClusterRole.
type RoleRef struct {
	Kind      string    `json:"kind"`
	Name      string    `json:"name"`
	Namespace string    `json:"namespace,omitempty"`
	UID       types.UID `json:"uid,omitempty"`
}

// Scanner identifies the tool that produced the report.
type Scanner struct {
	Name    string `json:"name"`
	Vendor  string `json:"vendor"`
	Version string `json:"version"`
}

// Report holds the violation list and the severity-bucket aggregation.
type Report struct {
	Checks  []Check `json:"checks"`
	Summary Summary `json:"summary"`
}

// Check describes one policy that was violated by the role. Multiple
// PolicyRules of the same role hitting the same policy are coalesced into
// a single Check with multiple Messages by the report builder.
type Check struct {
	CheckID     string   `json:"checkID"`
	Category    string   `json:"category"`
	Severity    Severity `json:"severity"`
	Title       string   `json:"title"`
	Description string   `json:"description,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
	Messages    []string `json:"messages"`
	// Success is always false in the current schema: the report only
	// contains violations. The field exists for Trivy schema compatibility.
	Success bool `json:"success"`
}

// Summary aggregates the per-severity violation counts. TotalCount is the
// sum of the four bucket counts and is set by the report builder.
type Summary struct {
	CriticalCount int `json:"criticalCount"`
	HighCount     int `json:"highCount"`
	MediumCount   int `json:"mediumCount"`
	LowCount      int `json:"lowCount"`
	TotalCount    int `json:"totalCount"`
}
