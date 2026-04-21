package subjectgraphreview

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

func TestCreate_UserQueryEmptyCluster(t *testing.T) {
	r := newTestREST()
	review := &rbacgraph.SubjectGraphReview{
		Spec: rbacgraph.SubjectGraphReviewSpec{
			Subject: rbacgraph.SubjectRef{Kind: rbacgraph.SubjectKindUser, Name: "alice"},
		},
	}

	result, err := r.Create(context.Background(), review, nil, &metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	resultReview, ok := result.(*rbacgraph.SubjectGraphReview)
	if !ok {
		t.Fatalf("expected *rbacgraph.SubjectGraphReview, got %T", result)
	}

	if resultReview.Status.Subject != review.Spec.Subject {
		t.Errorf("expected status.subject to echo spec.subject, got %+v", resultReview.Status.Subject)
	}
	// Subject node must always be present even in empty cluster.
	if len(resultReview.Status.Graph.Nodes) < 1 {
		t.Errorf("expected at least the subject node in empty cluster, got %d", len(resultReview.Status.Graph.Nodes))
	}
}

func TestCreate_DirectOnlySkipsGroups(t *testing.T) {
	r := newTestREST()
	review := &rbacgraph.SubjectGraphReview{
		Spec: rbacgraph.SubjectGraphReviewSpec{
			Subject:    rbacgraph.SubjectRef{Kind: rbacgraph.SubjectKindUser, Name: "alice"},
			DirectOnly: true,
		},
	}

	result, err := r.Create(context.Background(), review, nil, &metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	resultReview := result.(*rbacgraph.SubjectGraphReview)

	if got := len(resultReview.Status.ResolvedSubjects); got != 1 {
		t.Errorf("expected 1 resolved subject in direct-only mode, got %d", got)
	}
}

func TestCreate_MissingSubject(t *testing.T) {
	r := newTestREST()
	review := &rbacgraph.SubjectGraphReview{
		Spec: rbacgraph.SubjectGraphReviewSpec{},
	}

	_, err := r.Create(context.Background(), review, nil, &metav1.CreateOptions{})
	if err == nil {
		t.Fatal("expected validation error for missing subject.kind")
	}
}

func TestCreate_GroupWithNamespaceRejected(t *testing.T) {
	r := newTestREST()
	review := &rbacgraph.SubjectGraphReview{
		Spec: rbacgraph.SubjectGraphReviewSpec{
			Subject: rbacgraph.SubjectRef{
				Kind: rbacgraph.SubjectKindGroup, Name: "g", Namespace: "ns-a",
			},
		},
	}

	_, err := r.Create(context.Background(), review, nil, &metav1.CreateOptions{})
	if err == nil {
		t.Fatal("expected validation error for Group with namespace")
	}
}

func TestCreate_UnexpectedObjectType(t *testing.T) {
	r := newTestREST()
	_, err := r.Create(context.Background(), &rbacgraph.RoleGraphReview{}, nil, &metav1.CreateOptions{})
	if err == nil {
		t.Fatal("expected error for wrong object type")
	}
}
