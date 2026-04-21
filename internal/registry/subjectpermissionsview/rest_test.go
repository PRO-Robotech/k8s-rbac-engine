package subjectpermissionsview

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

func TestCreate_ServiceAccountQueryEmptyCluster(t *testing.T) {
	r := newTestREST()
	view := &rbacgraph.SubjectPermissionsView{
		Spec: rbacgraph.SubjectPermissionsViewSpec{
			Subject: rbacgraph.SubjectRef{
				Kind:      rbacgraph.SubjectKindServiceAccount,
				Namespace: "default",
				Name:      "foo",
			},
		},
	}

	result, err := r.Create(context.Background(), view, nil, &metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	resultView, ok := result.(*rbacgraph.SubjectPermissionsView)
	if !ok {
		t.Fatalf("expected *rbacgraph.SubjectPermissionsView, got %T", result)
	}

	if resultView.Status.Subject != view.Spec.Subject {
		t.Errorf("expected status.subject to echo spec.subject, got %+v", resultView.Status.Subject)
	}
	if resultView.CreationTimestamp.IsZero() {
		t.Error("expected CreationTimestamp to be set")
	}
	// Empty cluster: no roles/bindings, but resolvedSubjects should have SA + 3 implicit groups.
	if got := len(resultView.Status.ResolvedSubjects); got != 4 {
		t.Errorf("expected 4 resolved subjects for SA (incl. implicit groups), got %d", got)
	}
}

func TestCreate_MissingSubjectName(t *testing.T) {
	r := newTestREST()
	view := &rbacgraph.SubjectPermissionsView{
		Spec: rbacgraph.SubjectPermissionsViewSpec{
			Subject: rbacgraph.SubjectRef{Kind: rbacgraph.SubjectKindUser},
		},
	}

	_, err := r.Create(context.Background(), view, nil, &metav1.CreateOptions{})
	if err == nil {
		t.Fatal("expected validation error for missing subject.name")
	}
}

func TestCreate_InvalidSubjectKind(t *testing.T) {
	r := newTestREST()
	view := &rbacgraph.SubjectPermissionsView{
		Spec: rbacgraph.SubjectPermissionsViewSpec{
			Subject: rbacgraph.SubjectRef{Kind: "Robot", Name: "r2d2"},
		},
	}

	_, err := r.Create(context.Background(), view, nil, &metav1.CreateOptions{})
	if err == nil {
		t.Fatal("expected validation error for invalid subject.kind")
	}
}

func TestCreate_MissingSANamespace(t *testing.T) {
	r := newTestREST()
	view := &rbacgraph.SubjectPermissionsView{
		Spec: rbacgraph.SubjectPermissionsViewSpec{
			Subject: rbacgraph.SubjectRef{Kind: rbacgraph.SubjectKindServiceAccount, Name: "foo"},
		},
	}

	_, err := r.Create(context.Background(), view, nil, &metav1.CreateOptions{})
	if err == nil {
		t.Fatal("expected validation error for SA without namespace")
	}
}

func TestCreate_UnexpectedObjectType(t *testing.T) {
	r := newTestREST()
	_, err := r.Create(context.Background(), &rbacgraph.RoleGraphReview{}, nil, &metav1.CreateOptions{})
	if err == nil {
		t.Fatal("expected error for wrong object type")
	}
}
