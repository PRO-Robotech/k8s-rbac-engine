package subjectsbyselectorgraph

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

func TestCreate_BasicEmptyCluster(t *testing.T) {
	r := newTestREST()
	obj := &rbacgraph.SubjectsBySelectorGraph{
		Spec: rbacgraph.SubjectsBySelectorGraphSpec{
			Selector: rbacgraph.Selector{Verbs: []string{"get"}, Resources: []string{"secrets"}},
		},
	}

	result, err := r.Create(context.Background(), obj, nil, &metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	resultGraph, ok := result.(*rbacgraph.SubjectsBySelectorGraph)
	if !ok {
		t.Fatalf("expected *rbacgraph.SubjectsBySelectorGraph, got %T", result)
	}
	if len(resultGraph.Status.Graph.Nodes) != 0 {
		t.Errorf("expected 0 nodes in empty cluster, got %d", len(resultGraph.Status.Graph.Nodes))
	}
	if resultGraph.CreationTimestamp.IsZero() {
		t.Error("expected CreationTimestamp set")
	}
}

func TestCreate_EmptySelectorRejected(t *testing.T) {
	r := newTestREST()
	obj := &rbacgraph.SubjectsBySelectorGraph{
		Spec: rbacgraph.SubjectsBySelectorGraphSpec{Selector: rbacgraph.Selector{}},
	}

	_, err := r.Create(context.Background(), obj, nil, &metav1.CreateOptions{})
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
