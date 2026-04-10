package rolegraphreview

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/endpoints/request"
	fake "k8s.io/client-go/kubernetes/fake"

	"k8s-rbac-engine/internal/authz"
	"k8s-rbac-engine/pkg/apis/rbacgraph"
	"k8s-rbac-engine/pkg/engine"
	"k8s-rbac-engine/pkg/indexer"
)

func newTestREST(resolver authz.ScopeResolver) *REST {
	client := fake.NewSimpleClientset()
	idx := indexer.New(client, 0)
	eng := engine.New()

	return NewREST(eng, idx, nil, resolver)
}

func TestCreate_BasicQuery(t *testing.T) {
	r := newTestREST(nil)
	review := &rbacgraph.RoleGraphReview{
		ObjectMeta: metav1.ObjectMeta{Name: "test"},
		Spec: rbacgraph.RoleGraphReviewSpec{
			Selector: rbacgraph.Selector{
				Verbs:     []string{"get"},
				Resources: []string{"pods"},
			},
		},
	}

	result, err := r.Create(context.Background(), review, nil, &metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	resultReview, ok := result.(*rbacgraph.RoleGraphReview)
	if !ok {
		t.Fatalf("expected *rbacgraph.RoleGraphReview, got %T", result)
	}
	// With an empty snapshot, expect zero results.
	if resultReview.Status.MatchedRoles != 0 {
		t.Errorf("expected 0 matched roles from empty snapshot, got %d", resultReview.Status.MatchedRoles)
	}
}

func TestCreate_MissingSnapshot(t *testing.T) {
	// Indexer returns empty snapshot when it hasn't started — verify graceful handling.
	r := newTestREST(nil)
	review := &rbacgraph.RoleGraphReview{
		ObjectMeta: metav1.ObjectMeta{Name: "test"},
		Spec: rbacgraph.RoleGraphReviewSpec{
			Selector: rbacgraph.Selector{},
		},
	}

	result, err := r.Create(context.Background(), review, nil, &metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_ = result.(*rbacgraph.RoleGraphReview)
	// No data is expected — just verify it doesn't panic.
}

func TestCreate_WithScope(t *testing.T) {
	resolver := authz.NewLocalResolver(func() *indexer.Snapshot {
		// Return nil to trigger "snapshot not available" error.
		return nil
	})
	r := newTestREST(resolver)

	ctx := request.WithUser(context.Background(), &user.DefaultInfo{
		Name:   "test-user",
		Groups: []string{"system:authenticated"},
	})

	review := &rbacgraph.RoleGraphReview{
		ObjectMeta: metav1.ObjectMeta{Name: "test"},
		Spec: rbacgraph.RoleGraphReviewSpec{
			Selector: rbacgraph.Selector{
				Verbs:     []string{"get"},
				Resources: []string{"pods"},
			},
		},
	}

	_, err := r.Create(ctx, review, nil, &metav1.CreateOptions{})
	if err == nil {
		t.Fatal("expected error when resolver snapshot is nil")
	}
}

func TestCreate_WithScopeNoUserInfo(t *testing.T) {
	resolver := authz.NewLocalResolver(func() *indexer.Snapshot {
		return nil
	})
	r := newTestREST(resolver)

	review := &rbacgraph.RoleGraphReview{
		ObjectMeta: metav1.ObjectMeta{Name: "test"},
		Spec: rbacgraph.RoleGraphReviewSpec{
			Selector: rbacgraph.Selector{
				Verbs: []string{"get"},
			},
		},
	}

	// No user info in context.
	_, err := r.Create(context.Background(), review, nil, &metav1.CreateOptions{})
	if err == nil {
		t.Fatal("expected error when no user info in context")
	}
}

func TestCreate_WrongObjectType(t *testing.T) {
	r := newTestREST(nil)
	// Pass wrong type.
	_, err := r.Create(context.Background(), &metav1.Status{}, nil, &metav1.CreateOptions{})
	if err == nil {
		t.Fatal("expected error for wrong object type")
	}
}

func TestCollectNamespacesFromSnapshot(t *testing.T) {
	snap := &indexer.Snapshot{
		RolesByID: map[indexer.RoleID]*indexer.RoleRecord{
			"Role/ns-a/read": {Namespace: "ns-a", Name: "read"},
			"Role/ns-b/edit": {Namespace: "ns-b", Name: "edit"},
		},
		BindingsByRoleRef:     make(map[indexer.RoleRefKey][]*indexer.BindingRecord),
		PodsByServiceAccount:  make(map[indexer.ServiceAccountKey][]*indexer.PodRecord),
		WorkloadsByUID:        make(map[types.UID]*indexer.WorkloadRecord),
		AggregatedRoleSources: make(map[indexer.RoleID][]indexer.RoleID),
	}

	namespaces := collectNamespacesFromSnapshot(snap, rbacgraph.NamespaceScope{})
	nsSet := make(map[string]struct{})
	for _, ns := range namespaces {
		nsSet[ns] = struct{}{}
	}
	if _, ok := nsSet["ns-a"]; !ok {
		t.Error("expected ns-a in namespaces")
	}
	if _, ok := nsSet["ns-b"]; !ok {
		t.Error("expected ns-b in namespaces")
	}
}

func TestCollectNamespacesFromSnapshot_WithFilter(t *testing.T) {
	snap := &indexer.Snapshot{
		RolesByID: map[indexer.RoleID]*indexer.RoleRecord{
			"Role/ns-a/read": {Namespace: "ns-a", Name: "read"},
			"Role/ns-b/edit": {Namespace: "ns-b", Name: "edit"},
		},
		BindingsByRoleRef:     make(map[indexer.RoleRefKey][]*indexer.BindingRecord),
		PodsByServiceAccount:  make(map[indexer.ServiceAccountKey][]*indexer.PodRecord),
		WorkloadsByUID:        make(map[types.UID]*indexer.WorkloadRecord),
		AggregatedRoleSources: make(map[indexer.RoleID][]indexer.RoleID),
	}

	namespaces := collectNamespacesFromSnapshot(snap, rbacgraph.NamespaceScope{
		Namespaces: []string{"ns-a"},
	})
	if len(namespaces) != 1 || namespaces[0] != "ns-a" {
		t.Errorf("expected [ns-a], got %v", namespaces)
	}
}
