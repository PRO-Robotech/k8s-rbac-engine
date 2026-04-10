package engine

import (
	"testing"
	"time"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/types"

	api "k8s-rbac-engine/pkg/apis/rbacgraph"
	rrv1 "k8s-rbac-engine/pkg/apis/rbacreports/v1alpha1"
	"k8s-rbac-engine/pkg/indexer"
)

// makeMinimalSnapshot returns a single-role snapshot suitable for the
// enrichment tests. Selector matching against this snapshot uses
// (apiGroups=[""], resources=[pods], verbs=[get]).
func makeMinimalSnapshot(t *testing.T, role *indexer.RoleRecord) *indexer.Snapshot {
	t.Helper()

	roleID := indexer.RoleID(role.Kind + ":" + role.Namespace + "/" + role.Name)
	if role.Namespace == "" {
		roleID = indexer.RoleID(role.Kind + ":" + role.Name)
	}

	snap := &indexer.Snapshot{
		BuiltAt:           time.Now(),
		RolesByID:         map[indexer.RoleID]*indexer.RoleRecord{roleID: role},
		BindingsByRoleRef: map[indexer.RoleRefKey][]*indexer.BindingRecord{},
		AllRoleIDs:        []indexer.RoleID{roleID},
		RoleIDsByAPIGroup: map[string]map[indexer.RoleID]struct{}{
			"": {roleID: {}},
		},
		RoleIDsByResource: map[string]map[indexer.RoleID]struct{}{
			"pods": {roleID: {}},
		},
		RoleIDsByVerb: map[string]map[indexer.RoleID]struct{}{
			"get": {roleID: {}},
		},
	}

	return snap
}

func defaultSelector() api.RoleGraphReviewSpec {
	return api.RoleGraphReviewSpec{
		Selector: api.Selector{
			APIGroups: []string{""},
			Resources: []string{"pods"},
			Verbs:     []string{"get"},
		},
		MatchMode: api.MatchModeAny,
	}
}

func roleNodeFor(t *testing.T, status api.RoleGraphReviewStatus) *api.GraphNode {
	t.Helper()
	for i := range status.Graph.Nodes {
		switch status.Graph.Nodes[i].Type {
		case api.GraphNodeTypeRole, api.GraphNodeTypeClusterRole:
			return &status.Graph.Nodes[i]
		}
	}
	t.Fatalf("no role node in graph: %+v", status.Graph.Nodes)

	return nil
}

// TestQuery_NoLookup_AssessmentNil confirms Assessment is nil on role nodes
// when no ReportLookup is configured.
func TestQuery_NoLookup_AssessmentNil(t *testing.T) {
	role := &indexer.RoleRecord{
		UID:       types.UID("u1"),
		Kind:      indexer.KindClusterRole,
		Name:      "viewer",
		Rules:     []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}}},
		RuleCount: 1,
	}
	snap := makeMinimalSnapshot(t, role)

	e := New() // no ReportLookup
	status := e.Query(snap, defaultSelector(), nil)

	node := roleNodeFor(t, status)
	if node.Assessment != nil {
		t.Errorf("expected Assessment nil when no lookup configured; got %+v", node.Assessment)
	}
}

// TestQuery_LookupAttachesAssessment is the happy-path test: a configured
// MapReportLookup with a matching entry produces a populated Assessment on
// the role node.
func TestQuery_LookupAttachesAssessment(t *testing.T) {
	role := &indexer.RoleRecord{
		UID:       types.UID("u1"),
		Kind:      indexer.KindClusterRole,
		Name:      "cluster-admin",
		Rules:     []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}}},
		RuleCount: 1,
	}
	snap := makeMinimalSnapshot(t, role)

	lookup := NewMapReportLookup()
	lookup.Set(indexer.KindClusterRole, "", "cluster-admin", AssessmentFromCounts(2, 1, 0, 0, []string{"KSV044", "KSV050", "KSV041"}))

	e := New().WithReportLookup(lookup)
	status := e.Query(snap, defaultSelector(), nil)

	node := roleNodeFor(t, status)
	if node.Assessment == nil {
		t.Fatalf("expected Assessment to be populated")
	}
	a := node.Assessment
	if a.HighestSeverity != "CRITICAL" {
		t.Errorf("HighestSeverity = %q, want CRITICAL", a.HighestSeverity)
	}
	if a.CriticalCount != 2 || a.HighCount != 1 || a.TotalCount != 3 {
		t.Errorf("counts = %+v, want critical=2 high=1 total=3", a)
	}
	wantIDs := []string{"KSV041", "KSV044", "KSV050"} // sorted, deduplicated
	if len(a.CheckIDs) != 3 || a.CheckIDs[0] != wantIDs[0] || a.CheckIDs[1] != wantIDs[1] || a.CheckIDs[2] != wantIDs[2] {
		t.Errorf("CheckIDs = %v, want %v", a.CheckIDs, wantIDs)
	}
}

// TestQuery_LookupMissForKind confirms a lookup configured with a Role
// entry does NOT match a ClusterRole node with the same name (the (kind,
// namespace, name) tuple is the unique key).
func TestQuery_LookupMissForKind(t *testing.T) {
	role := &indexer.RoleRecord{
		UID:       types.UID("u1"),
		Kind:      indexer.KindClusterRole,
		Name:      "shared-name",
		Rules:     []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}}},
		RuleCount: 1,
	}
	snap := makeMinimalSnapshot(t, role)

	lookup := NewMapReportLookup()
	// Wrong kind: report exists for Role, not ClusterRole.
	lookup.Set(indexer.KindRole, "", "shared-name", AssessmentFromCounts(1, 0, 0, 0, nil))

	e := New().WithReportLookup(lookup)
	status := e.Query(snap, defaultSelector(), nil)
	node := roleNodeFor(t, status)
	if node.Assessment != nil {
		t.Errorf("expected Assessment nil for kind mismatch; got %+v", node.Assessment)
	}
}

// TestQuery_LookupNamespaceMatch tests namespaced Role enrichment.
func TestQuery_LookupNamespaceMatch(t *testing.T) {
	role := &indexer.RoleRecord{
		UID:       types.UID("u1"),
		Kind:      indexer.KindRole,
		Namespace: "istio-system",
		Name:      "istiod",
		Rules:     []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}}},
		RuleCount: 1,
	}
	snap := makeMinimalSnapshot(t, role)

	lookup := NewMapReportLookup()
	lookup.Set(indexer.KindRole, "istio-system", "istiod", AssessmentFromCounts(0, 0, 1, 0, []string{"KSV049"}))

	e := New().WithReportLookup(lookup)
	status := e.Query(snap, defaultSelector(), nil)

	node := roleNodeFor(t, status)
	if node.Assessment == nil {
		t.Fatalf("expected Assessment to be populated")
	}
	if node.Assessment.HighestSeverity != "MEDIUM" {
		t.Errorf("HighestSeverity = %q, want MEDIUM", node.Assessment.HighestSeverity)
	}
	if node.Assessment.MediumCount != 1 || node.Assessment.TotalCount != 1 {
		t.Errorf("counts = %+v", node.Assessment)
	}
}

// TestQuery_LookupCleanRole confirms a clean role (zero counts in lookup)
// still produces a non-nil Assessment with empty HighestSeverity.
func TestQuery_LookupCleanRole(t *testing.T) {
	role := &indexer.RoleRecord{
		UID:       types.UID("u1"),
		Kind:      indexer.KindClusterRole,
		Name:      "viewer",
		Rules:     []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}}},
		RuleCount: 1,
	}
	snap := makeMinimalSnapshot(t, role)

	lookup := NewMapReportLookup()
	lookup.Set(indexer.KindClusterRole, "", "viewer", AssessmentFromCounts(0, 0, 0, 0, nil))

	e := New().WithReportLookup(lookup)
	status := e.Query(snap, defaultSelector(), nil)

	node := roleNodeFor(t, status)
	if node.Assessment == nil {
		t.Fatalf("expected non-nil Assessment for clean role")
	}
	if node.Assessment.HighestSeverity != "" {
		t.Errorf("HighestSeverity = %q, want empty for clean role", node.Assessment.HighestSeverity)
	}
	if node.Assessment.TotalCount != 0 {
		t.Errorf("TotalCount = %d, want 0", node.Assessment.TotalCount)
	}
}

// TestHighestSeverity_Ordering covers the severity priority logic in
// isolation. CRITICAL outranks HIGH outranks MEDIUM outranks LOW.
func TestHighestSeverity_Ordering(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want string
	}{
		{"single-critical", []string{"CRITICAL"}, "CRITICAL"},
		{"mixed", []string{"LOW", "MEDIUM", "HIGH"}, "HIGH"},
		{"all-four", []string{"LOW", "CRITICAL", "MEDIUM", "HIGH"}, "CRITICAL"},
		{"low-only", []string{"LOW"}, "LOW"},
		{"unknown", []string{"PHANTOM"}, ""},
		{"empty", nil, ""},
		{"case-insensitive", []string{"high"}, "HIGH"},
		{"whitespace", []string{"  medium  "}, "MEDIUM"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := HighestSeverity(tt.in...); got != tt.want {
				t.Errorf("HighestSeverity(%v) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestAssessmentFromCounts_DeduplicatesCheckIDs verifies that the helper
// produces a sorted, deduplicated CheckIDs slice and computes
// HighestSeverity from the non-zero buckets.
func TestAssessmentFromCounts_DeduplicatesCheckIDs(t *testing.T) {
	a := AssessmentFromCounts(0, 2, 1, 3, []string{"KSV049", "KSV041", "KSV049", "KSV050"})
	if a.HighestSeverity != "HIGH" {
		t.Errorf("HighestSeverity = %q, want HIGH", a.HighestSeverity)
	}
	if a.TotalCount != 6 {
		t.Errorf("TotalCount = %d, want 6", a.TotalCount)
	}
	want := []string{"KSV041", "KSV049", "KSV050"}
	if len(a.CheckIDs) != len(want) {
		t.Fatalf("CheckIDs = %v, want %v", a.CheckIDs, want)
	}
	for i, id := range want {
		if a.CheckIDs[i] != id {
			t.Errorf("CheckIDs[%d] = %q, want %q", i, a.CheckIDs[i], id)
		}
	}
}

// TestMapReportLookup_NilSafeOnEmpty confirms a nil *MapReportLookup
// passed to lookupAssessmentForRole returns nil instead of panicking. This
// is important because the engine treats nil as "no lookup configured".
func TestMapReportLookup_NilSafeOnEmpty(t *testing.T) {
	var lookup *MapReportLookup
	if got := lookup.Lookup("Role", "ns", "x"); got != nil {
		t.Errorf("nil lookup must return nil, got %+v", got)
	}

	empty := NewMapReportLookup()
	if got := empty.Lookup("Role", "ns", "x"); got != nil {
		t.Errorf("empty lookup must return nil, got %+v", got)
	}
}

// TestAssessmentFromRbacReport covers the conversion from a fully-populated
// RbacReport (the kind a controller actually produces) into an Assessment.
// This is the helper that the report cache calls on every informer event.
func TestAssessmentFromRbacReport(t *testing.T) {
	report := &rrv1.RbacReport{
		Report: rrv1.Report{
			Checks: []rrv1.Check{
				{CheckID: "KSV049", Severity: rrv1.SeverityMedium},
				{CheckID: "KSV050", Severity: rrv1.SeverityCritical},
				{CheckID: "KSV049", Severity: rrv1.SeverityMedium}, // duplicate intentional
			},
			Summary: rrv1.Summary{
				CriticalCount: 1,
				HighCount:     0,
				MediumCount:   2,
				LowCount:      0,
				TotalCount:    3,
			},
		},
	}

	a := AssessmentFromRbacReport(report)
	if a == nil {
		t.Fatalf("AssessmentFromRbacReport returned nil")
	}
	if a.HighestSeverity != "CRITICAL" {
		t.Errorf("HighestSeverity = %q, want CRITICAL", a.HighestSeverity)
	}
	if a.CriticalCount != 1 || a.MediumCount != 2 || a.TotalCount != 3 {
		t.Errorf("counts = %+v", a)
	}
	// CheckIDs deduped + sorted alphabetically.
	want := []string{"KSV049", "KSV050"}
	if len(a.CheckIDs) != 2 || a.CheckIDs[0] != want[0] || a.CheckIDs[1] != want[1] {
		t.Errorf("CheckIDs = %v, want %v (deduped + sorted)", a.CheckIDs, want)
	}
}

// TestAssessmentFromRbacReport_Nil covers the nil-safety contract.
func TestAssessmentFromRbacReport_Nil(t *testing.T) {
	if got := AssessmentFromRbacReport(nil); got != nil {
		t.Errorf("nil report → nil assessment, got %+v", got)
	}
	if got := AssessmentFromClusterRbacReport(nil); got != nil {
		t.Errorf("nil cluster report → nil assessment, got %+v", got)
	}
}

// TestAssessmentFromClusterRbacReport mirrors the namespaced test but for
// ClusterRbacReport. The two helpers share an internal implementation but
// have separate public entry points so callers can't mix the kinds.
func TestAssessmentFromClusterRbacReport(t *testing.T) {
	report := &rrv1.ClusterRbacReport{
		Report: rrv1.Report{
			Checks: []rrv1.Check{
				{CheckID: "KSV044", Severity: rrv1.SeverityCritical},
			},
			Summary: rrv1.Summary{CriticalCount: 1, TotalCount: 1},
		},
	}
	a := AssessmentFromClusterRbacReport(report)
	if a == nil {
		t.Fatalf("nil assessment")
	}
	if a.HighestSeverity != "CRITICAL" || a.CriticalCount != 1 || a.TotalCount != 1 {
		t.Errorf("got %+v", a)
	}
	if len(a.CheckIDs) != 1 || a.CheckIDs[0] != "KSV044" {
		t.Errorf("CheckIDs = %v, want [KSV044]", a.CheckIDs)
	}
}
