package nonresourceurl

import (
	"context"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	fake "k8s.io/client-go/kubernetes/fake"

	"k8s-rbac-engine/pkg/apis/rbacgraph"
	"k8s-rbac-engine/pkg/indexer"
)

func newTestREST(roles map[indexer.RoleID]*indexer.RoleRecord) *REST {
	idx := indexer.New(fake.NewSimpleClientset(), 0)
	idx.SetSnapshotForTest(&indexer.Snapshot{
		RolesByID: roles,
	})

	return NewREST(idx)
}

func TestListNonResourceURLs(t *testing.T) {
	r := newTestREST(map[indexer.RoleID]*indexer.RoleRecord{
		"ClusterRole::metrics-reader": {
			Kind: "ClusterRole",
			Name: "metrics-reader",
			Rules: []rbacv1.PolicyRule{
				{NonResourceURLs: []string{"/metrics", "/healthz"}, Verbs: []string{"get"}},
			},
		},
		"ClusterRole::system:admin": {
			Kind: "ClusterRole",
			Name: "system:admin",
			Rules: []rbacv1.PolicyRule{
				{NonResourceURLs: []string{"/metrics", "/api/*"}, Verbs: []string{"get", "post"}},
				{Resources: []string{"pods"}, Verbs: []string{"get"}, APIGroups: []string{""}},
			},
		},
		"Role:ns:some-role": {
			Kind:      "Role",
			Namespace: "ns",
			Name:      "some-role",
			Rules: []rbacv1.PolicyRule{
				{Resources: []string{"configmaps"}, Verbs: []string{"get"}, APIGroups: []string{""}},
			},
		},
	})

	obj, err := r.List(context.Background(), nil)
	if err != nil {
		t.Fatalf("List() error: %v", err)
	}

	list, ok := obj.(*rbacgraph.NonResourceURLList)
	if !ok {
		t.Fatalf("expected *NonResourceURLList, got %T", obj)
	}

	if len(list.Items) != 3 {
		t.Fatalf("expected 3 entries, got %d: %+v", len(list.Items), list.Items)
	}

	expected := []struct {
		url       string
		verbCount int
		roleCount int
	}{
		{url: "/api/*", verbCount: 2, roleCount: 1},
		{url: "/healthz", verbCount: 1, roleCount: 1},
		{url: "/metrics", verbCount: 2, roleCount: 2},
	}

	for i, exp := range expected {
		entry := list.Items[i]
		if entry.URL != exp.url {
			t.Errorf("item[%d] URL = %q, want %q", i, entry.URL, exp.url)
		}
		if len(entry.Verbs) != exp.verbCount {
			t.Errorf("item[%d] verbs = %v (len %d), want len %d", i, entry.Verbs, len(entry.Verbs), exp.verbCount)
		}
		if len(entry.Roles) != exp.roleCount {
			t.Errorf("item[%d] roles = %v (len %d), want len %d", i, entry.Roles, len(entry.Roles), exp.roleCount)
		}
	}
}

func TestListEmpty(t *testing.T) {
	r := newTestREST(map[indexer.RoleID]*indexer.RoleRecord{})

	obj, err := r.List(context.Background(), nil)
	if err != nil {
		t.Fatalf("List() error: %v", err)
	}

	list := obj.(*rbacgraph.NonResourceURLList)
	if len(list.Items) != 0 {
		t.Errorf("expected 0 items, got %d", len(list.Items))
	}
}

func TestConvertToTable(t *testing.T) {
	r := &REST{}
	list := &rbacgraph.NonResourceURLList{
		Items: []rbacgraph.NonResourceURLEntry{
			{URL: "/metrics", Verbs: []string{"get"}, Roles: []string{"metrics-reader", "admin"}},
		},
	}

	table, err := r.ConvertToTable(context.Background(), list, nil)
	if err != nil {
		t.Fatalf("ConvertToTable() error: %v", err)
	}
	if len(table.Rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(table.Rows))
	}
	if table.Rows[0].Cells[0] != "/metrics" {
		t.Errorf("row[0] URL = %v, want /metrics", table.Rows[0].Cells[0])
	}
	if table.Rows[0].Cells[2] != 2 {
		t.Errorf("row[0] role count = %v, want 2", table.Rows[0].Cells[2])
	}
}
