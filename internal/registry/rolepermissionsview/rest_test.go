package rolepermissionsview

import (
	"context"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	fake "k8s.io/client-go/kubernetes/fake"

	"k8s-rbac-engine/pkg/apis/rbacgraph"
	"k8s-rbac-engine/pkg/indexer"
)

func newTestREST(roles map[indexer.RoleID]*indexer.RoleRecord) *REST {
	idx := indexer.New(fake.NewSimpleClientset(), 0)
	idx.SetSnapshotForTest(&indexer.Snapshot{
		RolesByID: roles,
	})

	return NewREST(idx, nil)
}

// newTestRESTWithDiscovery returns a REST handler whose underlying indexer has
// a synthetic discovery cache. The cache contains the supplied groups and the
// resources/verbs registered for each group.
func newTestRESTWithDiscovery(
	roles map[indexer.RoleID]*indexer.RoleRecord,
	resourcesByGroup map[string]map[string][]string,
) *REST {
	idx := indexer.New(fake.NewSimpleClientset(), 0)
	idx.SetSnapshotForTest(&indexer.Snapshot{RolesByID: roles})

	cache := &indexer.APIDiscoveryCache{
		Groups:               make(map[string]struct{}),
		ResourcesByGroup:     make(map[string]map[string]struct{}),
		VerbsByGroupResource: make(map[string]map[string][]string),
		AllResources:         make(map[string]struct{}),
		AllVerbs:             make(map[string]struct{}),
	}
	for group, resources := range resourcesByGroup {
		cache.Groups[group] = struct{}{}
		cache.ResourcesByGroup[group] = make(map[string]struct{})
		cache.VerbsByGroupResource[group] = make(map[string][]string)
		for resource, verbs := range resources {
			cache.ResourcesByGroup[group][resource] = struct{}{}
			cache.AllResources[resource] = struct{}{}
			cache.VerbsByGroupResource[group][resource] = verbs
			for _, v := range verbs {
				cache.AllVerbs[v] = struct{}{}
			}
		}
	}
	idx.SetDiscoveryCacheForTest(cache)

	return NewREST(idx, nil)
}

func TestCreate_ClusterRole(t *testing.T) {
	r := newTestREST(map[indexer.RoleID]*indexer.RoleRecord{
		"clusterrole:admin": {
			Kind: "ClusterRole",
			Name: "admin",
			Rules: []rbacv1.PolicyRule{
				{APIGroups: []string{""}, Resources: []string{"pods", "services"}, Verbs: []string{"get", "list"}},
				{NonResourceURLs: []string{"/metrics"}, Verbs: []string{"get"}},
			},
		},
	})

	view := &rbacgraph.RolePermissionsView{
		Spec: rbacgraph.RolePermissionsViewSpec{
			Role: rbacgraph.RoleRef{Kind: "ClusterRole", Name: "admin"},
		},
	}

	obj, err := r.Create(context.Background(), view, nil, &metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	result := obj.(*rbacgraph.RolePermissionsView)

	if result.Status.Name != "admin" {
		t.Errorf("status.name = %q, want %q", result.Status.Name, "admin")
	}
	if result.Status.Scope != rbacgraph.RoleScopeCluster {
		t.Errorf("status.scope = %q, want %q", result.Status.Scope, rbacgraph.RoleScopeCluster)
	}
	if len(result.Status.APIGroups) != 1 {
		t.Fatalf("expected 1 API group, got %d", len(result.Status.APIGroups))
	}

	ag := result.Status.APIGroups[0]
	if ag.APIGroup != "core" {
		t.Errorf("apiGroup = %q, want %q", ag.APIGroup, "core")
	}
	if ag.ResourcesCount != 2 {
		t.Errorf("resourcesCount = %d, want 2", ag.ResourcesCount)
	}

	// Check pods verbs
	foundPods := false
	for _, res := range ag.Resources {
		if res.Plural == "pods" {
			foundPods = true
			if len(res.Verbs) != 2 {
				t.Errorf("pods verbs count = %d, want 2", len(res.Verbs))
			}
			for _, verb := range []string{"get", "list"} {
				vp, ok := res.Verbs[verb]
				if !ok {
					t.Errorf("pods missing verb %q", verb)
				}
				if !vp.Granted {
					t.Errorf("pods verb %q not granted", verb)
				}
			}
		}
	}
	if !foundPods {
		t.Error("expected pods in resources")
	}

	// Check nonResourceURLs
	if result.Status.NonResourceURLs == nil {
		t.Fatal("expected nonResourceUrls to be non-nil")
	}
	if result.Status.NonResourceURLs.URLsCount != 1 {
		t.Errorf("urlsCount = %d, want 1", result.Status.NonResourceURLs.URLsCount)
	}
	if result.Status.NonResourceURLs.URLs[0].URL != "/metrics" {
		t.Errorf("url = %q, want /metrics", result.Status.NonResourceURLs.URLs[0].URL)
	}
}

func TestCreate_NamespacedRole(t *testing.T) {
	r := newTestREST(map[indexer.RoleID]*indexer.RoleRecord{
		"role:default/reader": {
			Kind:      "Role",
			Namespace: "default",
			Name:      "reader",
			Rules: []rbacv1.PolicyRule{
				{APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"get"}},
			},
		},
	})

	view := &rbacgraph.RolePermissionsView{
		Spec: rbacgraph.RolePermissionsViewSpec{
			Role: rbacgraph.RoleRef{Kind: "role", Name: "reader", Namespace: "default"},
		},
	}

	obj, err := r.Create(context.Background(), view, nil, &metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	result := obj.(*rbacgraph.RolePermissionsView)
	if result.Status.Scope != rbacgraph.RoleScopeNamespace {
		t.Errorf("scope = %q, want namespace", result.Status.Scope)
	}
	if len(result.Status.APIGroups) != 1 || result.Status.APIGroups[0].ResourcesCount != 1 {
		t.Error("expected 1 apiGroup with 1 resource")
	}
}

func TestCreate_NotFound(t *testing.T) {
	r := newTestREST(map[indexer.RoleID]*indexer.RoleRecord{})

	view := &rbacgraph.RolePermissionsView{
		Spec: rbacgraph.RolePermissionsViewSpec{
			Role: rbacgraph.RoleRef{Kind: "ClusterRole", Name: "nonexistent"},
		},
	}

	_, err := r.Create(context.Background(), view, nil, &metav1.CreateOptions{})
	if err == nil {
		t.Fatal("expected error for nonexistent role")
	}
}

func TestCreate_SelectorFilter(t *testing.T) {
	r := newTestREST(map[indexer.RoleID]*indexer.RoleRecord{
		"clusterrole:admin": {
			Kind: "ClusterRole",
			Name: "admin",
			Rules: []rbacv1.PolicyRule{
				{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get", "list", "create"}},
				{APIGroups: []string{""}, Resources: []string{"services"}, Verbs: []string{"get"}},
				{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"get"}},
			},
		},
	})

	view := &rbacgraph.RolePermissionsView{
		Spec: rbacgraph.RolePermissionsViewSpec{
			Role: rbacgraph.RoleRef{Kind: "ClusterRole", Name: "admin"},
			Selector: rbacgraph.Selector{
				Resources: []string{"pods"},
			},
		},
	}

	obj, err := r.Create(context.Background(), view, nil, &metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	result := obj.(*rbacgraph.RolePermissionsView)
	if len(result.Status.APIGroups) != 1 {
		t.Fatalf("expected 1 API group (filtered), got %d", len(result.Status.APIGroups))
	}
	if result.Status.APIGroups[0].ResourcesCount != 1 {
		t.Errorf("expected 1 resource (pods only), got %d", result.Status.APIGroups[0].ResourcesCount)
	}
	if result.Status.APIGroups[0].Resources[0].Plural != "pods" {
		t.Errorf("expected pods, got %q", result.Status.APIGroups[0].Resources[0].Plural)
	}
}

func TestCreate_ValidationErrors(t *testing.T) {
	r := newTestREST(map[indexer.RoleID]*indexer.RoleRecord{
		"clusterrole:dummy": {Kind: "ClusterRole", Name: "dummy"},
	})

	tests := []struct {
		name string
		spec rbacgraph.RolePermissionsViewSpec
	}{
		{
			name: "empty name",
			spec: rbacgraph.RolePermissionsViewSpec{Role: rbacgraph.RoleRef{Kind: "ClusterRole"}},
		},
		{
			name: "invalid kind",
			spec: rbacgraph.RolePermissionsViewSpec{Role: rbacgraph.RoleRef{Kind: "invalid", Name: "test"}},
		},
		{
			name: "role without namespace",
			spec: rbacgraph.RolePermissionsViewSpec{Role: rbacgraph.RoleRef{Kind: "role", Name: "test", Namespace: ""}},
		},
		{
			name: "invalid wildcardMode",
			spec: rbacgraph.RolePermissionsViewSpec{
				Role:         rbacgraph.RoleRef{Kind: "ClusterRole", Name: "dummy"},
				WildcardMode: "bogus",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			view := &rbacgraph.RolePermissionsView{Spec: tt.spec}
			_, err := r.Create(context.Background(), view, nil, &metav1.CreateOptions{})
			if err == nil {
				t.Error("expected error")
			}
		})
	}
}

// TestCreate_WildcardMode_Exact verifies that exact mode preserves "*" as a
// literal token instead of fanning it out via discovery, so the response shows
// a single "*" pseudo-resource rather than every known API.
func TestCreate_WildcardMode_Exact(t *testing.T) {
	r := newTestRESTWithDiscovery(
		map[indexer.RoleID]*indexer.RoleRecord{
			"clusterrole:wildcard-admin": {
				Kind: "ClusterRole",
				Name: "wildcard-admin",
				Rules: []rbacv1.PolicyRule{
					{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}},
				},
			},
		},
		map[string]map[string][]string{
			"": {
				"pods":     {"get", "list", "create"},
				"services": {"get", "list"},
			},
			"apps": {
				"deployments": {"get", "list"},
			},
		},
	)

	view := &rbacgraph.RolePermissionsView{
		Spec: rbacgraph.RolePermissionsViewSpec{
			Role:         rbacgraph.RoleRef{Kind: "ClusterRole", Name: "wildcard-admin"},
			WildcardMode: rbacgraph.WildcardModeExact,
		},
	}

	obj, err := r.Create(context.Background(), view, nil, &metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}
	result := obj.(*rbacgraph.RolePermissionsView)

	// In exact mode the wildcard rule must collapse to a single (*, *, *) entry
	// instead of being expanded against every group/resource in discovery.
	if len(result.Status.APIGroups) != 1 {
		t.Fatalf("expected 1 apiGroup in exact mode, got %d", len(result.Status.APIGroups))
	}
	ag := result.Status.APIGroups[0]
	if ag.ResourcesCount != 1 || ag.Resources[0].Plural != "*" {
		t.Fatalf("expected single '*' resource, got %+v", ag.Resources)
	}
	if _, ok := ag.Resources[0].Verbs["*"]; !ok {
		t.Errorf("expected '*' verb in exact mode, got verbs=%v", ag.Resources[0].Verbs)
	}
}

// TestCreate_WildcardMode_DefaultResolves confirms that the default wildcard
// mode still resolves "*" against discovery (preserving today's behaviour for
// callers that don't pass wildcardMode).
func TestCreate_WildcardMode_DefaultResolves(t *testing.T) {
	r := newTestRESTWithDiscovery(
		map[indexer.RoleID]*indexer.RoleRecord{
			"clusterrole:wildcard-admin": {
				Kind: "ClusterRole",
				Name: "wildcard-admin",
				Rules: []rbacv1.PolicyRule{
					{APIGroups: []string{""}, Resources: []string{"*"}, Verbs: []string{"get"}},
				},
			},
		},
		map[string]map[string][]string{
			"": {
				"pods":     {"get", "list"},
				"services": {"get", "list"},
			},
		},
	)

	view := &rbacgraph.RolePermissionsView{
		Spec: rbacgraph.RolePermissionsViewSpec{
			Role: rbacgraph.RoleRef{Kind: "ClusterRole", Name: "wildcard-admin"},
			// WildcardMode left empty → defaults to wildcard.
		},
	}

	obj, err := r.Create(context.Background(), view, nil, &metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}
	result := obj.(*rbacgraph.RolePermissionsView)

	if len(result.Status.APIGroups) != 1 || result.Status.APIGroups[0].ResourcesCount != 2 {
		t.Fatalf("expected expansion to 2 resources, got %+v", result.Status.APIGroups)
	}
}

// TestCreate_FilterPhantomAPIs verifies that resources missing from discovery
// (e.g. CRDs that are no longer installed) are dropped when the caller asks
// for the "real by OpenAPI" view.
func TestCreate_FilterPhantomAPIs(t *testing.T) {
	r := newTestRESTWithDiscovery(
		map[indexer.RoleID]*indexer.RoleRecord{
			"clusterrole:operator": {
				Kind: "ClusterRole",
				Name: "operator",
				Rules: []rbacv1.PolicyRule{
					{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}},
					// "ghosts" is a phantom resource — not in discovery.
					{APIGroups: []string{"missing.example.com"}, Resources: []string{"ghosts"}, Verbs: []string{"get"}},
				},
			},
		},
		map[string]map[string][]string{
			"": {"pods": {"get", "list"}},
		},
	)

	view := &rbacgraph.RolePermissionsView{
		Spec: rbacgraph.RolePermissionsViewSpec{
			Role:              rbacgraph.RoleRef{Kind: "ClusterRole", Name: "operator"},
			FilterPhantomAPIs: true,
		},
	}

	obj, err := r.Create(context.Background(), view, nil, &metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}
	result := obj.(*rbacgraph.RolePermissionsView)

	if len(result.Status.APIGroups) != 1 {
		t.Fatalf("expected only the real apiGroup after phantom filter, got %d: %+v",
			len(result.Status.APIGroups), result.Status.APIGroups)
	}
	if result.Status.APIGroups[0].APIGroup != "core" {
		t.Errorf("expected core group to remain, got %q", result.Status.APIGroups[0].APIGroup)
	}
}

// TestCreate_FilterPhantomAPIs_Disabled is the negative case: with the flag
// off the phantom rule still appears, just marked Phantom=true.
func TestCreate_FilterPhantomAPIs_Disabled(t *testing.T) {
	r := newTestRESTWithDiscovery(
		map[indexer.RoleID]*indexer.RoleRecord{
			"clusterrole:operator": {
				Kind: "ClusterRole",
				Name: "operator",
				Rules: []rbacv1.PolicyRule{
					{APIGroups: []string{"missing.example.com"}, Resources: []string{"ghosts"}, Verbs: []string{"get"}},
				},
			},
		},
		map[string]map[string][]string{
			"": {"pods": {"get"}},
		},
	)

	view := &rbacgraph.RolePermissionsView{
		Spec: rbacgraph.RolePermissionsViewSpec{
			Role: rbacgraph.RoleRef{Kind: "ClusterRole", Name: "operator"},
			// FilterPhantomAPIs left off.
		},
	}

	obj, err := r.Create(context.Background(), view, nil, &metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}
	result := obj.(*rbacgraph.RolePermissionsView)

	if len(result.Status.APIGroups) != 1 {
		t.Fatalf("expected phantom group to remain, got %d", len(result.Status.APIGroups))
	}
	if !result.Status.APIGroups[0].Resources[0].Phantom {
		t.Errorf("expected phantom flag to be set on the phantom resource")
	}
}
