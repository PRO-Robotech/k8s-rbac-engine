package engine

import (
	"sort"

	api "k8s-rbac-engine/pkg/apis/rbacgraph"
	rrv1 "k8s-rbac-engine/pkg/apis/rbacreports/v1alpha1"
	"k8s-rbac-engine/pkg/indexer"
)

// ReportLookup returns the assessment for a role, or nil if none exists.
// Implementations must be safe for concurrent use.
type ReportLookup interface {
	Lookup(kind, namespace, name string) *api.Assessment
}

// MapReportLookup is an in-memory ReportLookup keyed on (kind, namespace, name).
type MapReportLookup struct {
	entries map[lookupKey]*api.Assessment
}

type lookupKey struct {
	kind      string
	namespace string
	name      string
}

// NewMapReportLookup returns an empty MapReportLookup.
func NewMapReportLookup() *MapReportLookup {
	return &MapReportLookup{entries: make(map[lookupKey]*api.Assessment)}
}

// Set associates an assessment with a role identity.
func (m *MapReportLookup) Set(kind, namespace, name string, assessment *api.Assessment) {
	if m.entries == nil {
		m.entries = make(map[lookupKey]*api.Assessment)
	}
	m.entries[lookupKey{kind: kind, namespace: namespace, name: name}] = assessment
}

// Lookup implements ReportLookup.
func (m *MapReportLookup) Lookup(kind, namespace, name string) *api.Assessment {
	if m == nil || len(m.entries) == 0 {
		return nil
	}

	return m.entries[lookupKey{kind: kind, namespace: namespace, name: name}]
}

// HighestSeverity returns the worst of the provided severities, or "" if none recognized.
func HighestSeverity(severities ...string) string {
	best := ""
	bestRank := 0
	for _, s := range severities {
		sev := rrv1.ParseSeverity(s)
		rank, ok := sev.Priority()
		if !ok {
			continue
		}
		if best == "" || rank < bestRank {
			best = string(sev)
			bestRank = rank
		}
	}

	return best
}

// AssessmentFromCounts builds an Assessment from per-severity counts and CheckIDs.
// CheckIDs are de-duplicated and sorted.
func AssessmentFromCounts(critical, high, medium, low int, checkIDs []string) *api.Assessment {
	a := &api.Assessment{
		CriticalCount: critical,
		HighCount:     high,
		MediumCount:   medium,
		LowCount:      low,
		TotalCount:    critical + high + medium + low,
	}

	switch {
	case critical > 0:
		a.HighestSeverity = string(rrv1.SeverityCritical)
	case high > 0:
		a.HighestSeverity = string(rrv1.SeverityHigh)
	case medium > 0:
		a.HighestSeverity = string(rrv1.SeverityMedium)
	case low > 0:
		a.HighestSeverity = string(rrv1.SeverityLow)
	}

	if len(checkIDs) > 0 {
		seen := make(map[string]struct{}, len(checkIDs))
		uniq := make([]string, 0, len(checkIDs))
		for _, id := range checkIDs {
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			uniq = append(uniq, id)
		}
		sort.Strings(uniq)
		a.CheckIDs = uniq
	}

	return a
}

// lookupAssessmentForRole returns the assessment for a role, or nil if lookup is nil or misses.
func lookupAssessmentForRole(lookup ReportLookup, role *indexer.RoleRecord) *api.Assessment {
	if lookup == nil {
		return nil
	}

	return lookup.Lookup(role.Kind, role.Namespace, role.Name)
}

// AssessmentFromRbacReport converts a RbacReport into an Assessment.
func AssessmentFromRbacReport(r *rrv1.RbacReport) *api.Assessment {
	if r == nil {
		return nil
	}

	return assessmentFromReportCommon(r.Report)
}

// AssessmentFromClusterRbacReport converts a ClusterRbacReport into an Assessment.
func AssessmentFromClusterRbacReport(r *rrv1.ClusterRbacReport) *api.Assessment {
	if r == nil {
		return nil
	}

	return assessmentFromReportCommon(r.Report)
}

func assessmentFromReportCommon(report rrv1.Report) *api.Assessment {
	checkIDs := make([]string, 0, len(report.Checks))
	for i := range report.Checks {
		if id := report.Checks[i].CheckID; id != "" {
			checkIDs = append(checkIDs, id)
		}
	}

	return AssessmentFromCounts(
		report.Summary.CriticalCount,
		report.Summary.HighCount,
		report.Summary.MediumCount,
		report.Summary.LowCount,
		checkIDs,
	)
}
