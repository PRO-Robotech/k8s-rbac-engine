package indexer

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	fakediscovery "k8s.io/client-go/discovery/fake"
	fakeclientset "k8s.io/client-go/kubernetes/fake"

	api "k8s-rbac-engine/pkg/apis/rbacgraph"
)

// fakeDiscoveryWithResources returns a discovery client pre-loaded with the
// given resource lists.
func fakeDiscoveryWithResources(resourceLists []*metav1.APIResourceList) *fakediscovery.FakeDiscovery {
	cs := fakeclientset.NewSimpleClientset()
	fd := cs.Discovery().(*fakediscovery.FakeDiscovery)
	fd.Resources = resourceLists

	return fd
}

// standardResourceLists returns a typical set of API resource lists for testing.
func standardResourceLists() []*metav1.APIResourceList {
	return []*metav1.APIResourceList{
		{
			GroupVersion: "v1",
			APIResources: []metav1.APIResource{
				{Name: "pods", Verbs: metav1.Verbs{"get", "list", "watch", "create", "delete"}},
				{Name: "pods/exec", Verbs: metav1.Verbs{"create"}},
				{Name: "pods/log", Verbs: metav1.Verbs{"get"}},
				{Name: "services", Verbs: metav1.Verbs{"get", "list", "create", "update", "delete"}},
				{Name: "configmaps", Verbs: metav1.Verbs{"get", "list", "create", "update", "patch", "delete"}},
			},
		},
		{
			GroupVersion: "apps/v1",
			APIResources: []metav1.APIResource{
				{Name: "deployments", Verbs: metav1.Verbs{"get", "list", "create", "update", "delete"}},
				{Name: "replicasets", Verbs: metav1.Verbs{"get", "list", "create", "update", "delete"}},
			},
		},
		{
			GroupVersion: "batch/v1",
			APIResources: []metav1.APIResource{
				{Name: "jobs", Verbs: metav1.Verbs{"get", "list", "create", "delete"}},
				{Name: "cronjobs", Verbs: metav1.Verbs{"get", "list", "create", "delete"}},
			},
		},
	}
}

func TestGroupFromGroupVersion(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"v1", ""},
		{"apps/v1", "apps"},
		{"batch/v1", "batch"},
		{"rbac.authorization.k8s.io/v1", "rbac.authorization.k8s.io"},
		{"networking.k8s.io/v1", "networking.k8s.io"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := groupFromGroupVersion(tt.input)
			if got != tt.want {
				t.Fatalf("groupFromGroupVersion(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestBuildDiscoveryCache_Standard(t *testing.T) {
	fd := fakeDiscoveryWithResources(standardResourceLists())
	cache, err := buildDiscoveryCache(fd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Check groups.
	for _, g := range []string{"", "apps", "batch"} {
		if _, ok := cache.Groups[g]; !ok {
			t.Errorf("expected group %q in cache", g)
		}
	}

	// Check resources in specific groups.
	if _, ok := cache.ResourcesByGroup[""]["pods"]; !ok {
		t.Error("expected pods in core group")
	}
	if _, ok := cache.ResourcesByGroup[""]["pods/exec"]; !ok {
		t.Error("expected pods/exec in core group")
	}
	if _, ok := cache.ResourcesByGroup["apps"]["deployments"]; !ok {
		t.Error("expected deployments in apps group")
	}

	// Check AllResources.
	for _, r := range []string{"pods", "pods/exec", "services", "deployments", "jobs"} {
		if _, ok := cache.AllResources[r]; !ok {
			t.Errorf("expected %q in AllResources", r)
		}
	}

	// Check verbs.
	for _, v := range []string{"get", "list", "create", "update", "delete", "watch", "patch"} {
		if _, ok := cache.AllVerbs[v]; !ok {
			t.Errorf("expected verb %q in AllVerbs", v)
		}
	}

	// Check VerbsByGroupResource.
	if cache.VerbsByGroupResource == nil {
		t.Fatal("expected VerbsByGroupResource to be non-nil")
	}
	coreVerbs := cache.VerbsByGroupResource[""]
	if coreVerbs == nil {
		t.Fatal("expected core group in VerbsByGroupResource")
	}
	podsVerbs := coreVerbs["pods"]
	if len(podsVerbs) == 0 {
		t.Fatal("expected verbs for pods resource")
	}
	// Verbs should be sorted.
	for i := 1; i < len(podsVerbs); i++ {
		if podsVerbs[i] < podsVerbs[i-1] {
			t.Fatalf("expected sorted verbs, got %v", podsVerbs)
		}
	}
	// pods/exec should have "create".
	execVerbs := coreVerbs["pods/exec"]
	if len(execVerbs) != 1 || execVerbs[0] != "create" {
		t.Fatalf("expected pods/exec verbs=[create], got %v", execVerbs)
	}
	// apps group deployments.
	appsVerbs := cache.VerbsByGroupResource["apps"]
	if appsVerbs == nil {
		t.Fatal("expected apps group in VerbsByGroupResource")
	}
	if deplVerbs := appsVerbs["deployments"]; len(deplVerbs) == 0 {
		t.Fatal("expected verbs for deployments")
	}
}

func TestBuildDiscoveryCache_Empty(t *testing.T) {
	fd := fakeDiscoveryWithResources(nil)
	cache, err := buildDiscoveryCache(fd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cache.Groups) != 0 {
		t.Errorf("expected empty groups, got %d", len(cache.Groups))
	}
}

func TestContainsWildcard(t *testing.T) {
	tests := []struct {
		name  string
		input []string
		want  bool
	}{
		{"nil", nil, false},
		{"empty", []string{}, false},
		{"no wildcard", []string{"apps", "batch"}, false},
		{"has wildcard", []string{"apps", "*"}, true},
		{"only wildcard", []string{"*"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := containsWildcard(tt.input); got != tt.want {
				t.Fatalf("containsWildcard(%v) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// indexerWithDiscoveryCache creates an Indexer with a pre-loaded discovery cache
// (no informer factory needed for validation tests).
func indexerWithDiscoveryCache(cache *APIDiscoveryCache) *Indexer {
	i := &Indexer{}
	if cache != nil {
		i.discoveryCache.Store(cache)
	}

	return i
}

func buildTestCache(t *testing.T) *APIDiscoveryCache {
	t.Helper()
	fd := fakeDiscoveryWithResources(standardResourceLists())
	cache, err := buildDiscoveryCache(fd)
	if err != nil {
		t.Fatalf("unexpected error building test cache: %v", err)
	}

	return cache
}

func TestValidateSelector_ValidInputs(t *testing.T) {
	cache := buildTestCache(t)
	idx := indexerWithDiscoveryCache(cache)

	tests := []struct {
		name string
		sel  api.Selector
	}{
		{"empty selector", api.Selector{}},
		{"valid apiGroup", api.Selector{APIGroups: []string{"apps"}}},
		{"core group", api.Selector{APIGroups: []string{""}}},
		{"valid resource", api.Selector{Resources: []string{"pods"}}},
		{"valid subresource", api.Selector{Resources: []string{"pods/exec"}}},
		{"valid verb", api.Selector{Verbs: []string{"get"}}},
		{"wildcard apiGroups", api.Selector{APIGroups: []string{"*"}}},
		{"wildcard resources", api.Selector{Resources: []string{"*"}}},
		{"wildcard verbs", api.Selector{Verbs: []string{"*"}}},
		{"mixed wildcard apiGroups", api.Selector{APIGroups: []string{"apps", "*"}}},
		{"resource in constrained group", api.Selector{APIGroups: []string{"apps"}, Resources: []string{"deployments"}}},
		{"resourceNames not validated", api.Selector{ResourceNames: []string{"anything-goes"}}},
		{"nonResourceURLs not validated", api.Selector{NonResourceURLs: []string{"/metrics"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := idx.ValidateSelector(tt.sel); err != nil {
				t.Fatalf("expected no error, got: %v", err)
			}
		})
	}
}

func TestValidateSelector_InvalidAPIGroups(t *testing.T) {
	cache := buildTestCache(t)
	idx := indexerWithDiscoveryCache(cache)

	sel := api.Selector{APIGroups: []string{"nonexistent"}}
	err := idx.ValidateSelector(sel)
	if err == nil {
		t.Fatal("expected error for unknown apiGroup")
	}
	t.Logf("got expected error: %v", err)
}

func TestValidateSelector_InvalidResources(t *testing.T) {
	cache := buildTestCache(t)
	idx := indexerWithDiscoveryCache(cache)

	tests := []struct {
		name string
		sel  api.Selector
	}{
		{"unknown resource unconstrained", api.Selector{Resources: []string{"foobar"}}},
		{"resource not in specified group", api.Selector{APIGroups: []string{"apps"}, Resources: []string{"pods"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := idx.ValidateSelector(tt.sel)
			if err == nil {
				t.Fatal("expected error for unknown resource")
			}
			t.Logf("got expected error: %v", err)
		})
	}
}

func TestValidateSelector_InvalidVerbs(t *testing.T) {
	cache := buildTestCache(t)
	idx := indexerWithDiscoveryCache(cache)

	sel := api.Selector{Verbs: []string{"fly"}}
	err := idx.ValidateSelector(sel)
	if err == nil {
		t.Fatal("expected error for unknown verb")
	}
	t.Logf("got expected error: %v", err)
}

func TestValidateSelector_NilCache(t *testing.T) {
	// When discovery cache is nil (fetch failed), validation should be skipped.
	// indexerWithDiscoveryCache(nil) leaves the atomic pointer at zero-value.
	idx := indexerWithDiscoveryCache(nil)

	sel := api.Selector{APIGroups: []string{"nonexistent"}, Resources: []string{"foobar"}, Verbs: []string{"fly"}}
	if err := idx.ValidateSelector(sel); err != nil {
		t.Fatalf("expected nil cache to skip validation, got: %v", err)
	}
}

func TestValidateSelector_CrossGroupResourceCheck(t *testing.T) {
	cache := buildTestCache(t)
	idx := indexerWithDiscoveryCache(cache)

	// "jobs" exists in "batch" but not in "apps" — when apiGroups=["batch"], it should be valid.
	sel := api.Selector{APIGroups: []string{"batch"}, Resources: []string{"jobs"}}
	if err := idx.ValidateSelector(sel); err != nil {
		t.Fatalf("expected jobs to be valid in batch group, got: %v", err)
	}

	// But when apiGroups=["apps"], "jobs" should be invalid.
	sel = api.Selector{APIGroups: []string{"apps"}, Resources: []string{"jobs"}}
	if err := idx.ValidateSelector(sel); err == nil {
		t.Fatal("expected error for jobs in apps group")
	}
}
