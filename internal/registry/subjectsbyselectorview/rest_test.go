package subjectsbyselectorview

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	fake "k8s.io/client-go/kubernetes/fake"

	"k8s-rbac-engine/pkg/apis/rbacgraph"
	"k8s-rbac-engine/pkg/engine"
	"k8s-rbac-engine/pkg/indexer"
)

func newTestREST() *REST {
	client := fake.NewSimpleClientset()
	idx := indexer.New(client, 0)
	eng := engine.New()

	return NewREST(eng, idx, nil)
}

func TestCreate_BasicSelectorEmptyCluster(t *testing.T) {
	r := newTestREST()
	view := &rbacgraph.SubjectsBySelectorView{
		Spec: rbacgraph.SubjectsBySelectorViewSpec{
			Selector: rbacgraph.Selector{Verbs: []string{"get"}, Resources: []string{"secrets"}},
		},
	}

	result, err := r.Create(context.Background(), view, nil, &metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	resultView, ok := result.(*rbacgraph.SubjectsBySelectorView)
	if !ok {
		t.Fatalf("expected *rbacgraph.SubjectsBySelectorView, got %T", result)
	}
	if len(resultView.Status.Subjects) != 0 {
		t.Errorf("expected 0 subjects in empty cluster, got %d", len(resultView.Status.Subjects))
	}
	if resultView.Status.ExpandedImplicitGroups {
		t.Error("expected expandedImplicitGroups=false by default")
	}
	if resultView.CreationTimestamp.IsZero() {
		t.Error("expected CreationTimestamp set")
	}
}

func TestCreate_ExpandFlagEchoesInStatus(t *testing.T) {
	r := newTestREST()
	view := &rbacgraph.SubjectsBySelectorView{
		Spec: rbacgraph.SubjectsBySelectorViewSpec{
			Selector:             rbacgraph.Selector{Verbs: []string{"get"}},
			ExpandImplicitGroups: true,
		},
	}

	result, err := r.Create(context.Background(), view, nil, &metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	resultView := result.(*rbacgraph.SubjectsBySelectorView)
	if !resultView.Status.ExpandedImplicitGroups {
		t.Error("expected expandedImplicitGroups=true to round-trip into status")
	}
}

func TestCreate_EmptySelectorRejected(t *testing.T) {
	r := newTestREST()
	view := &rbacgraph.SubjectsBySelectorView{
		Spec: rbacgraph.SubjectsBySelectorViewSpec{Selector: rbacgraph.Selector{}},
	}

	_, err := r.Create(context.Background(), view, nil, &metav1.CreateOptions{})
	if err == nil {
		t.Fatal("expected validation error for empty selector")
	}
}

func TestCreate_UnexpectedObjectType(t *testing.T) {
	r := newTestREST()
	_, err := r.Create(context.Background(), &rbacgraph.RoleGraphReview{}, nil, &metav1.CreateOptions{})
	if err == nil {
		t.Fatal("expected error for wrong object type")
	}
}
