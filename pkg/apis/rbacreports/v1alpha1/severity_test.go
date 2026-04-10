package v1alpha1

import "testing"

// TestSeverityPriority pins the canonical severity ordering.
func TestSeverityPriority(t *testing.T) {
	cases := []struct {
		s        Severity
		wantRank int
		wantOK   bool
	}{
		{SeverityCritical, 0, true},
		{SeverityHigh, 1, true},
		{SeverityMedium, 2, true},
		{SeverityLow, 3, true},
		{Severity(""), 0, false},
		{Severity("INFO"), 0, false},
		{Severity("critical"), 0, false}, // not normalized; ParseSeverity does that
	}
	for _, tc := range cases {
		t.Run(string(tc.s), func(t *testing.T) {
			rank, ok := tc.s.Priority()
			if ok != tc.wantOK {
				t.Errorf("Priority(%q).ok = %v, want %v", tc.s, ok, tc.wantOK)
			}
			if ok && rank != tc.wantRank {
				t.Errorf("Priority(%q).rank = %d, want %d", tc.s, rank, tc.wantRank)
			}
		})
	}

	// Strict ordering: CRITICAL < HIGH < MEDIUM < LOW.
	known := []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow}
	prev, _ := known[0].Priority()
	for _, s := range known[1:] {
		cur, _ := s.Priority()
		if cur <= prev {
			t.Fatalf("ordering broken: %s rank %d not strictly greater than previous %d", s, cur, prev)
		}
		prev = cur
	}
}

// TestParseSeverity verifies case-insensitive, whitespace-trimmed parsing
// and that unknowns map to the empty Severity.
func TestParseSeverity(t *testing.T) {
	cases := []struct {
		in   string
		want Severity
	}{
		{"CRITICAL", SeverityCritical},
		{"critical", SeverityCritical},
		{"  Critical  ", SeverityCritical},
		{"HIGH", SeverityHigh},
		{"medium", SeverityMedium},
		{"low", SeverityLow},
		{"INFO", ""},
		{"", ""},
		{"   ", ""},
		{"phantom", ""},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			if got := ParseSeverity(tc.in); got != tc.want {
				t.Errorf("ParseSeverity(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
