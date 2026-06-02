package engine

import (
	"testing"
	"time"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/types"

	api "k8s-rbac-engine/pkg/apis/rbacgraph"
	"k8s-rbac-engine/pkg/indexer"
)

// FilterPhantomAPIs must drop phantom refs from aggregated nodes even when
// the node is reached as another role's aggregation source.
func TestAggregationSourceBypass_FilterPhantomAPIs(t *testing.T) {
	snapshot, discovery := aggregatedPhantomSnapshot()
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
			if ref.APIGroup == "custom.io" {
				t.Fatalf("node %q: phantom ref custom.io/%s/%s leaked despite filterPhantomAPIs=true (aggregation source bypass): %+v",
					node.ID, ref.Resource, ref.Subresource, ref)
			}
		}
	}
	for _, edge := range status.Graph.Edges {
		for _, ref := range edge.RuleRefs {
			if ref.APIGroup == "custom.io" {
				t.Fatalf("edge %q: phantom ref custom.io/%s/%s leaked into edge.ruleRefs: %+v",
					edge.ID, ref.Resource, ref.Subresource, ref)
			}
		}
	}
}

// With filtering off, phantom refs reach every node but must uniformly carry
// phantom=true, including nodes reached via aggregation source iteration.
func TestAggregationSourceBypass_AnnotatedWhenFilterOff(t *testing.T) {
	snapshot, discovery := aggregatedPhantomSnapshot()
	e := New()

	status := e.Query(snapshot, api.RoleGraphReviewSpec{
		Selector: api.Selector{
			Resources: []string{"pods/exec"},
		},
		IncludeRuleMetadata: true,
	}, discovery)

	annotated := 0
	bare := 0
	for _, node := range status.Graph.Nodes {
		for _, ref := range node.MatchedRuleRefs {
			if ref.APIGroup != "custom.io" {
				continue
			}
			if ref.Phantom {
				annotated++
			} else {
				bare++
				t.Errorf("node %q: ref custom.io/%s/%s should carry phantom=true but doesn't: %+v",
					node.ID, ref.Resource, ref.Subresource, ref)
			}
		}
	}
	if annotated == 0 {
		t.Fatalf("expected phantom-annotated refs on at least one role node, got none")
	}
	if bare > 0 {
		t.Fatalf("%d refs reached nodes without phantom annotation — aggregation source bypass", bare)
	}
}

// aggregatedPhantomSnapshot builds a higher → target → source aggregation
// chain where every role rules on custom.io/pods/exec (phantom: discovery
// knows custom.io/pods but not the exec subresource). Only higher also rules
// on the real core/pods/exec.
func aggregatedPhantomSnapshot() (*indexer.Snapshot, *indexer.APIDiscoveryCache) {
	snapshot := minimalSnapshot()
	snapshot.AggregatedRoleSources = map[indexer.RoleID][]indexer.RoleID{}

	phantomRule := rbacv1.PolicyRule{
		APIGroups: []string{"custom.io"},
		Resources: []string{"pods/exec"},
		Verbs:     []string{"get", "list", "watch"},
	}
	realRule := rbacv1.PolicyRule{
		APIGroups: []string{""},
		Resources: []string{"pods/exec"},
		Verbs:     []string{"create"},
	}

	roles := []struct {
		uid   string
		name  string
		rules []rbacv1.PolicyRule
	}{
		{"r-higher", "higher", []rbacv1.PolicyRule{phantomRule, realRule}},
		{"r-target", "target", []rbacv1.PolicyRule{phantomRule}},
		{"r-source", "source", []rbacv1.PolicyRule{phantomRule}},
	}
	for _, r := range roles {
		role := &indexer.RoleRecord{
			UID:   types.UID(r.uid),
			Kind:  indexer.KindClusterRole,
			Name:  r.name,
			Rules: r.rules,
		}
		roleID := indexer.RecID(indexer.KindClusterRole, "", r.name)
		snapshot.RolesByID[roleID] = role
		snapshot.AllRoleIDs = append(snapshot.AllRoleIDs, roleID)

		if snapshot.RoleIDsByResource["pods/exec"] == nil {
			snapshot.RoleIDsByResource["pods/exec"] = map[indexer.RoleID]struct{}{}
		}
		snapshot.RoleIDsByResource["pods/exec"][roleID] = struct{}{}
	}

	higherID := indexer.RecID(indexer.KindClusterRole, "", "higher")
	targetID := indexer.RecID(indexer.KindClusterRole, "", "target")
	sourceID := indexer.RecID(indexer.KindClusterRole, "", "source")
	snapshot.AggregatedRoleSources[higherID] = []indexer.RoleID{targetID}
	snapshot.AggregatedRoleSources[targetID] = []indexer.RoleID{sourceID}

	binding := &indexer.BindingRecord{
		UID:      types.UID("b-higher"),
		Kind:     indexer.KindClusterRoleBinding,
		Name:     "bind-higher",
		RoleRef:  indexer.RoleRefKey{Kind: indexer.KindClusterRole, Name: "higher"},
		Subjects: []rbacv1.Subject{{Kind: indexer.SubjectKindUser, Name: "alice"}},
	}
	snapshot.BindingsByRoleRef[binding.RoleRef] = []*indexer.BindingRecord{binding}

	discovery := &indexer.APIDiscoveryCache{
		Groups: map[string]struct{}{"": {}, "custom.io": {}},
		ResourcesByGroup: map[string]map[string]struct{}{
			"":          {"pods": {}, "pods/exec": {}},
			"custom.io": {"pods": {}},
		},
		AllResources: map[string]struct{}{"pods": {}, "pods/exec": {}},
		AllVerbs:     map[string]struct{}{"get": {}, "list": {}, "watch": {}, "create": {}},
		FetchedAt:    time.Now(),
	}

	return snapshot, discovery
}
