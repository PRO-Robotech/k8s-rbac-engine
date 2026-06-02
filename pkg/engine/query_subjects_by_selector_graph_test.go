package engine_test

import (
	"testing"

	api "k8s-rbac-engine/pkg/apis/rbacgraph"
	"k8s-rbac-engine/pkg/engine"
)

func TestQuerySubjectsBySelectorGraph_BuildsSubjectRootedGraph(t *testing.T) {
	s := buildSelectorTestSnapshot()
	e := engine.New()

	status := e.QuerySubjectsBySelectorGraph(s, api.SubjectsBySelectorGraphSpec{
		Selector: api.Selector{Resources: []string{"secrets"}, Verbs: []string{"get"}},
	}, nil)

	if status.MatchedRoles == 0 {
		t.Fatalf("expected non-zero matchedRoles, got 0")
	}
	if status.MatchedBindings == 0 {
		t.Fatalf("expected non-zero matchedBindings, got 0")
	}
	if status.MatchedSubjects == 0 {
		t.Fatalf("expected non-zero matchedSubjects, got 0")
	}
	if len(status.Graph.Nodes) == 0 {
		t.Fatal("expected non-empty graph nodes")
	}
	if len(status.Graph.Edges) == 0 {
		t.Fatal("expected non-empty graph edges")
	}
}

func TestQuerySubjectsBySelectorGraph_GrantsAndSubjectsEdges(t *testing.T) {
	s := buildSelectorTestSnapshot()
	e := engine.New()

	status := e.QuerySubjectsBySelectorGraph(s, api.SubjectsBySelectorGraphSpec{
		Selector: api.Selector{Resources: []string{"secrets"}, Verbs: []string{"get"}},
	}, nil)

	hasGrantsEdge := false
	hasSubjectsEdge := false
	for _, e := range status.Graph.Edges {
		switch e.Type {
		case api.GraphEdgeTypeGrants:
			hasGrantsEdge = true
			if len(e.RuleRefs) == 0 {
				t.Errorf("grants edge missing ruleRefs: %+v", e)
			}
		case api.GraphEdgeTypeSubjects:
			hasSubjectsEdge = true
		}
	}
	if !hasGrantsEdge {
		t.Error("expected at least one grants edge (binding → role)")
	}
	if !hasSubjectsEdge {
		t.Error("expected at least one subjects edge (subject → binding)")
	}
}

func TestQuerySubjectsBySelectorGraph_ExpandAddsConcreteSAs(t *testing.T) {
	s := buildSelectorTestSnapshot()
	extendSnapshotWithServiceAccounts(s)
	e := engine.New()

	literal := e.QuerySubjectsBySelectorGraph(s, api.SubjectsBySelectorGraphSpec{
		Selector: api.Selector{Resources: []string{"secrets"}, Verbs: []string{"get"}},
	}, nil)
	expanded := e.QuerySubjectsBySelectorGraph(s, api.SubjectsBySelectorGraphSpec{
		Selector:             api.Selector{Resources: []string{"secrets"}, Verbs: []string{"get"}},
		ExpandImplicitGroups: true,
	}, nil)

	if expanded.MatchedSubjects <= literal.MatchedSubjects {
		t.Errorf("expected expanded to have more subjects than literal (literal=%d, expanded=%d) — fixture has system:authenticated binding on view, should resolve to 3 SAs",
			literal.MatchedSubjects, expanded.MatchedSubjects)
	}
}

func TestQuerySubjectsBySelectorGraph_EmptyMatch(t *testing.T) {
	s := buildSelectorTestSnapshot()
	e := engine.New()

	status := e.QuerySubjectsBySelectorGraph(s, api.SubjectsBySelectorGraphSpec{
		Selector: api.Selector{Resources: []string{"nonexistent"}, Verbs: []string{"get"}},
	}, nil)

	if status.MatchedRoles != 0 || len(status.Graph.Nodes) != 0 {
		t.Errorf("expected empty graph for non-matching selector, got %d roles, %d nodes",
			status.MatchedRoles, len(status.Graph.Nodes))
	}
}
