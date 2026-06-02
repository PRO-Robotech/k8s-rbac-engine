package engine

import (
	"testing"
	"time"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/types"

	api "k8s-rbac-engine/pkg/apis/rbacgraph"
	"k8s-rbac-engine/pkg/indexer"
)

// An explicit subresource must match discovery exactly: metrics.k8s.io/pods/exec
// stays phantom even though metrics.k8s.io/pods (PodMetrics) exists.
func TestPhantomSubresource_BaseResourceFallback_DoesNotFalseAccept(t *testing.T) {
	snapshot, discovery := metricsPhantomSnapshot()
	e := New()

	status := e.Query(snapshot, api.RoleGraphReviewSpec{
		Selector: api.Selector{
			Resources: []string{"pods/exec"},
		},
		FilterPhantomAPIs:   true,
		IncludeRuleMetadata: true,
	}, discovery)

	for _, node := range status.Graph.Nodes {
		for _, ref := range node.MatchedRuleRefs {
			if ref.APIGroup == "metrics.k8s.io" {
				t.Fatalf("metrics.k8s.io/%s/%s should have been filtered as phantom, got %+v",
					ref.Resource, ref.Subresource, ref)
			}
		}
	}
	for _, edge := range status.Graph.Edges {
		for _, ref := range edge.RuleRefs {
			if ref.APIGroup == "metrics.k8s.io" {
				t.Fatalf("metrics.k8s.io ref leaked into edge.ruleRefs: %+v", ref)
			}
		}
	}
}

// TestPhantomSubresource_AnnotatedWhenFilterOff verifies the warning + phantom
// flag are emitted when filtering is off.
func TestPhantomSubresource_AnnotatedWhenFilterOff(t *testing.T) {
	snapshot, discovery := metricsPhantomSnapshot()
	e := New()

	status := e.Query(snapshot, api.RoleGraphReviewSpec{
		Selector: api.Selector{
			Resources: []string{"pods/exec"},
		},
		IncludeRuleMetadata: true,
	}, discovery)

	found := false
	for _, node := range status.Graph.Nodes {
		for _, ref := range node.MatchedRuleRefs {
			if ref.APIGroup == "metrics.k8s.io" && ref.Phantom {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected metrics.k8s.io/pods/exec ref to carry phantom=true")
	}

	if !contains(status.Warnings, `subresource "pods/exec" in API group "metrics.k8s.io" is not registered in the cluster`) {
		t.Errorf("expected subresource phantom warning, got %v", status.Warnings)
	}
}

// Not phantom when discovery lists the full subresource key.
func TestPhantomSubresource_ExplicitSubresourceInDiscoveryNotPhantom(t *testing.T) {
	snapshot, discovery := metricsPhantomSnapshot()
	// Pretend metrics.k8s.io actually had pods/exec (synthetic).
	discovery.ResourcesByGroup["metrics.k8s.io"]["pods/exec"] = struct{}{}

	e := New()
	status := e.Query(snapshot, api.RoleGraphReviewSpec{
		Selector: api.Selector{
			Resources: []string{"pods/exec"},
		},
		IncludeRuleMetadata: true,
	}, discovery)

	for _, node := range status.Graph.Nodes {
		for _, ref := range node.MatchedRuleRefs {
			if ref.APIGroup == "metrics.k8s.io" && ref.Phantom {
				t.Fatalf("metrics.k8s.io/pods/exec should not be phantom when discovery lists it, got %+v", ref)
			}
		}
	}
}

// Refs without a subresource still use the base-resource fallback.
func TestPhantomSubresource_NoSubresourcePreservesFallback(t *testing.T) {
	// Role grants pods (no subresource) on metrics.k8s.io.
	snapshot := minimalSnapshot()
	role := &indexer.RoleRecord{
		UID:  types.UID("r-base"),
		Kind: indexer.KindClusterRole,
		Name: "metrics-base",
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{"metrics.k8s.io"},
			Resources: []string{"pods"},
			Verbs:     []string{"get"},
		}},
	}
	roleID := indexer.RoleID("clusterrole:metrics-base")
	snapshot.RolesByID[roleID] = role
	snapshot.AllRoleIDs = []indexer.RoleID{roleID}
	snapshot.RoleIDsByAPIGroup["metrics.k8s.io"] = map[indexer.RoleID]struct{}{roleID: {}}
	snapshot.RoleIDsByResource["pods"] = map[indexer.RoleID]struct{}{roleID: {}}
	snapshot.RoleIDsByVerb["get"] = map[indexer.RoleID]struct{}{roleID: {}}

	binding := &indexer.BindingRecord{
		UID:      types.UID("b-base"),
		Kind:     indexer.KindClusterRoleBinding,
		Name:     "bind-metrics-base",
		RoleRef:  indexer.RoleRefKey{Kind: indexer.KindClusterRole, Name: "metrics-base"},
		Subjects: []rbacv1.Subject{{Kind: indexer.SubjectKindUser, Name: "alice"}},
	}
	snapshot.BindingsByRoleRef[binding.RoleRef] = []*indexer.BindingRecord{binding}

	// Discovery has metrics.k8s.io/pods (PodMetrics) — base lookup wins.
	discovery := &indexer.APIDiscoveryCache{
		Groups:           map[string]struct{}{"": {}, "metrics.k8s.io": {}},
		ResourcesByGroup: map[string]map[string]struct{}{"metrics.k8s.io": {"pods": {}}},
		AllResources:     map[string]struct{}{"pods": {}},
		AllVerbs:         map[string]struct{}{"get": {}},
		FetchedAt:        time.Now(),
	}

	e := New()
	status := e.Query(snapshot, api.RoleGraphReviewSpec{
		Selector:            api.Selector{Resources: []string{"pods"}, Verbs: []string{"get"}},
		IncludeRuleMetadata: true,
	}, discovery)

	for _, node := range status.Graph.Nodes {
		for _, ref := range node.MatchedRuleRefs {
			if ref.APIGroup == "metrics.k8s.io" && ref.Phantom {
				t.Fatalf("metrics.k8s.io/pods (no subresource) should not be phantom when base exists, got %+v", ref)
			}
		}
	}
}

// metricsPhantomSnapshot: a wildcard-resource role over core + metrics.k8s.io,
// where metrics.k8s.io has base pods but not the pods/exec subresource.
func metricsPhantomSnapshot() (*indexer.Snapshot, *indexer.APIDiscoveryCache) {
	snapshot := minimalSnapshot()

	role := &indexer.RoleRecord{
		UID:  types.UID("r-wide"),
		Kind: indexer.KindClusterRole,
		Name: "allow-read-all",
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{"", "metrics.k8s.io"},
			Resources: []string{"*"},
			Verbs:     []string{"get", "list", "watch"},
		}},
	}
	roleID := indexer.RoleID("clusterrole:allow-read-all")
	snapshot.RolesByID[roleID] = role
	snapshot.AllRoleIDs = []indexer.RoleID{roleID}
	snapshot.RoleIDsByAPIGroup[""] = map[indexer.RoleID]struct{}{roleID: {}}
	snapshot.RoleIDsByAPIGroup["metrics.k8s.io"] = map[indexer.RoleID]struct{}{roleID: {}}
	snapshot.RoleIDsByResource["*"] = map[indexer.RoleID]struct{}{roleID: {}}
	snapshot.RoleIDsByVerb["get"] = map[indexer.RoleID]struct{}{roleID: {}}

	binding := &indexer.BindingRecord{
		UID:      types.UID("b-wide"),
		Kind:     indexer.KindClusterRoleBinding,
		Name:     "bind-allow-read-all",
		RoleRef:  indexer.RoleRefKey{Kind: indexer.KindClusterRole, Name: "allow-read-all"},
		Subjects: []rbacv1.Subject{{Kind: indexer.SubjectKindUser, Name: "alice"}},
	}
	snapshot.BindingsByRoleRef[binding.RoleRef] = []*indexer.BindingRecord{binding}

	// core has pods + pods/exec; metrics.k8s.io has only base pods.
	discovery := &indexer.APIDiscoveryCache{
		Groups: map[string]struct{}{"": {}, "metrics.k8s.io": {}},
		ResourcesByGroup: map[string]map[string]struct{}{
			"":               {"pods": {}, "pods/exec": {}},
			"metrics.k8s.io": {"pods": {}},
		},
		AllResources: map[string]struct{}{"pods": {}, "pods/exec": {}},
		AllVerbs:     map[string]struct{}{"get": {}, "list": {}, "watch": {}},
		FetchedAt:    time.Now(),
	}

	return snapshot, discovery
}

func minimalSnapshot() *indexer.Snapshot {
	return &indexer.Snapshot{
		BuiltAt:           time.Now(),
		RolesByID:         map[indexer.RoleID]*indexer.RoleRecord{},
		BindingsByRoleRef: map[indexer.RoleRefKey][]*indexer.BindingRecord{},
		RoleIDsByVerb:     map[string]map[indexer.RoleID]struct{}{},
		RoleIDsByResource: map[string]map[indexer.RoleID]struct{}{},
		RoleIDsByAPIGroup: map[string]map[indexer.RoleID]struct{}{},
		AllRoleIDs:        []indexer.RoleID{},
	}
}
