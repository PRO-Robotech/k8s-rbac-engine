package engine

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	api "k8s-rbac-engine/pkg/apis/rbacgraph"
	"k8s-rbac-engine/pkg/apis/rbacgraph/v1alpha1"
	"k8s-rbac-engine/pkg/indexer"
)

func TestQuery_BuildsGraph(t *testing.T) {
	snapshot := &indexer.Snapshot{
		BuiltAt:           time.Now(),
		RolesByID:         map[indexer.RoleID]*indexer.RoleRecord{},
		BindingsByRoleRef: map[indexer.RoleRefKey][]*indexer.BindingRecord{},
		RoleIDsByVerb:     map[string]map[indexer.RoleID]struct{}{},
		RoleIDsByResource: map[string]map[indexer.RoleID]struct{}{},
		RoleIDsByAPIGroup: map[string]map[indexer.RoleID]struct{}{},
		AllRoleIDs:        []indexer.RoleID{},
	}

	role := &indexer.RoleRecord{
		UID:       types.UID("r1"),
		Kind:      indexer.KindClusterRole,
		Name:      "exec-role",
		Namespace: "",
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{""},
			Resources: []string{"pods/exec"},
			Verbs:     []string{"create"},
		}},
	}

	roleID := indexer.RoleID("clusterrole:exec-role")
	snapshot.RolesByID[roleID] = role
	snapshot.AllRoleIDs = []indexer.RoleID{roleID}
	snapshot.RoleIDsByAPIGroup[""] = map[indexer.RoleID]struct{}{roleID: {}}
	snapshot.RoleIDsByResource["pods/exec"] = map[indexer.RoleID]struct{}{roleID: {}}
	snapshot.RoleIDsByVerb["create"] = map[indexer.RoleID]struct{}{roleID: {}}

	binding := &indexer.BindingRecord{
		UID:      types.UID("b1"),
		Kind:     indexer.KindClusterRoleBinding,
		Name:     "bind-exec",
		RoleRef:  indexer.RoleRefKey{Kind: indexer.KindClusterRole, Name: "exec-role"},
		Subjects: []rbacv1.Subject{{Kind: indexer.SubjectKindUser, Name: "alice"}},
	}
	snapshot.BindingsByRoleRef[binding.RoleRef] = []*indexer.BindingRecord{binding}

	e := New()
	status := e.Query(snapshot, api.RoleGraphReviewSpec{
		Selector: api.Selector{
			APIGroups: []string{""},
			Resources: []string{"pods/exec"},
			Verbs:     []string{"create"},
		},
		MatchMode:           api.MatchModeAny,
		IncludeRuleMetadata: true,
	}, nil)

	if status.MatchedRoles != 1 {
		t.Fatalf("expected 1 matched role, got %d", status.MatchedRoles)
	}
	if status.MatchedBindings != 1 {
		t.Fatalf("expected 1 matched binding, got %d", status.MatchedBindings)
	}
	if status.MatchedSubjects != 1 {
		t.Fatalf("expected 1 matched subject, got %d", status.MatchedSubjects)
	}
	if len(status.Graph.Nodes) != 3 {
		t.Fatalf("expected 3 nodes, got %d", len(status.Graph.Nodes))
	}
	if len(status.Graph.Edges) != 2 {
		t.Fatalf("expected 2 edges, got %d", len(status.Graph.Edges))
	}
	if len(status.ResourceMap) == 0 {
		t.Fatalf("expected resource map entries")
	}
}

func TestQuery_AnnotatesAggregatedClusterRoles(t *testing.T) {
	snapshot := &indexer.Snapshot{
		BuiltAt:               time.Now(),
		RolesByID:             map[indexer.RoleID]*indexer.RoleRecord{},
		BindingsByRoleRef:     map[indexer.RoleRefKey][]*indexer.BindingRecord{},
		AggregatedRoleSources: map[indexer.RoleID][]indexer.RoleID{},
		RoleIDsByVerb:         map[string]map[indexer.RoleID]struct{}{},
		RoleIDsByResource:     map[string]map[indexer.RoleID]struct{}{},
		RoleIDsByAPIGroup:     map[string]map[indexer.RoleID]struct{}{},
		AllRoleIDs:            []indexer.RoleID{},
	}

	sourceRole := &indexer.RoleRecord{
		UID:  types.UID("src"),
		Kind: indexer.KindClusterRole,
		Name: "aggregate-to-edit-source",
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{""},
			Resources: []string{"pods/exec"},
			Verbs:     []string{"get"},
		}},
	}
	aggregatedRole := &indexer.RoleRecord{
		UID:  types.UID("agg"),
		Kind: indexer.KindClusterRole,
		Name: "edit",
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{""},
			Resources: []string{"pods/exec"},
			Verbs:     []string{"get"},
		}},
	}

	sourceRoleID := indexer.RoleID("clusterrole:aggregate-to-edit-source")
	aggregatedRoleID := indexer.RoleID("clusterrole:edit")
	snapshot.RolesByID[sourceRoleID] = sourceRole
	snapshot.RolesByID[aggregatedRoleID] = aggregatedRole
	snapshot.AllRoleIDs = []indexer.RoleID{aggregatedRoleID}
	snapshot.AggregatedRoleSources[aggregatedRoleID] = []indexer.RoleID{sourceRoleID}
	snapshot.RoleIDsByAPIGroup[""] = map[indexer.RoleID]struct{}{aggregatedRoleID: {}}
	snapshot.RoleIDsByResource["pods/exec"] = map[indexer.RoleID]struct{}{aggregatedRoleID: {}}
	snapshot.RoleIDsByVerb["get"] = map[indexer.RoleID]struct{}{aggregatedRoleID: {}}

	binding := &indexer.BindingRecord{
		UID:      types.UID("b1"),
		Kind:     indexer.KindClusterRoleBinding,
		Name:     "bind-edit",
		RoleRef:  indexer.RoleRefKey{Kind: indexer.KindClusterRole, Name: "edit"},
		Subjects: []rbacv1.Subject{{Kind: indexer.SubjectKindUser, Name: "bob"}},
	}
	snapshot.BindingsByRoleRef[binding.RoleRef] = []*indexer.BindingRecord{binding}

	e := New()
	status := e.Query(snapshot, api.RoleGraphReviewSpec{
		Selector: api.Selector{
			APIGroups: []string{""},
			Resources: []string{"pods/exec"},
			Verbs:     []string{"get"},
		},
		MatchMode:           api.MatchModeAny,
		IncludeRuleMetadata: true,
	}, nil)

	var hasAggregatedNode bool
	var hasAggregatesEdge bool
	for _, node := range status.Graph.Nodes {
		if node.Name != "edit" {
			continue
		}
		hasAggregatedNode = node.Aggregated && len(node.AggregationSources) == 1 && node.AggregationSources[0] == string(sourceRoleID)
	}
	for _, edge := range status.Graph.Edges {
		if edge.Type == api.GraphEdgeTypeAggregates && strings.Contains(edge.ID, "aggregate-to-edit-source") && strings.Contains(edge.ID, "edit") {
			hasAggregatesEdge = true
		}
	}

	if !hasAggregatedNode {
		t.Fatalf("expected aggregated node metadata for edit clusterrole")
	}
	if !hasAggregatesEdge {
		t.Fatalf("expected aggregates edge between source and target clusterrole")
	}
}

func TestQuery_RuntimeChainServiceAccountToWorkload(t *testing.T) {
	snapshot := runtimeSnapshotForTests()
	e := New()

	status := e.Query(snapshot, api.RoleGraphReviewSpec{
		Selector: api.Selector{
			Resources: []string{"pods/exec"},
			Verbs:     []string{"get"},
		},
		IncludePods:      true,
		IncludeWorkloads: true,
		PodPhaseMode:     api.PodPhaseModeActive,
	}, nil)

	if status.MatchedPods != 1 {
		t.Fatalf("expected 1 matched pod, got %d", status.MatchedPods)
	}
	if status.MatchedWorkloads != 2 {
		t.Fatalf("expected 2 matched workloads, got %d", status.MatchedWorkloads)
	}

	assertHasNodeType(t, status.Graph.Nodes, api.GraphNodeTypePod)
	assertHasNodeType(t, status.Graph.Nodes, api.GraphNodeTypeWorkload)
	assertHasEdgeType(t, status.Graph.Edges, api.GraphEdgeTypeRunsAs)
	assertHasEdgeType(t, status.Graph.Edges, api.GraphEdgeTypeOwnedBy)
}

func TestQuery_RuntimeIncludeWorkloadsAutoEnablesPods(t *testing.T) {
	snapshot := runtimeSnapshotForTests()
	e := New()

	status := e.Query(snapshot, api.RoleGraphReviewSpec{
		Selector: api.Selector{
			Resources: []string{"pods/exec"},
			Verbs:     []string{"get"},
		},
		IncludeWorkloads: true,
	}, nil)

	if status.MatchedPods == 0 {
		t.Fatalf("expected pods to be included when includeWorkloads=true")
	}
	if !contains(status.Warnings, "includeWorkloads=true requires includePods=true; includePods was enabled automatically") {
		t.Fatalf("expected warning about auto-enabled includePods, warnings=%v", status.Warnings)
	}
}

func TestQuery_RuntimeLimitsAndPhaseFilter(t *testing.T) {
	snapshot := runtimeSnapshotForTests()
	saKey := indexer.ServiceAccountKey{Namespace: "team", Name: "demo-sa"}
	snapshot.PodsByServiceAccount[saKey] = append(snapshot.PodsByServiceAccount[saKey], &indexer.PodRecord{
		UID:                types.UID("pod-2"),
		Namespace:          "team",
		Name:               "pending-pod",
		ServiceAccountName: "demo-sa",
		Phase:              corev1.PodPending,
		OwnerReferences:    nil,
	})
	snapshot.PodsByServiceAccount[saKey] = append(snapshot.PodsByServiceAccount[saKey], &indexer.PodRecord{
		UID:                types.UID("pod-3"),
		Namespace:          "team",
		Name:               "running-pod-2",
		ServiceAccountName: "demo-sa",
		Phase:              corev1.PodRunning,
		OwnerReferences: []metav1.OwnerReference{{
			APIVersion: "apps/v1",
			Kind:       "ReplicaSet",
			Name:       "demo-rs",
			UID:        types.UID("rs-1"),
		}},
	})

	e := New()
	status := e.Query(snapshot, api.RoleGraphReviewSpec{
		Selector: api.Selector{
			Resources: []string{"pods/exec"},
			Verbs:     []string{"get"},
		},
		IncludePods:         true,
		IncludeWorkloads:    true,
		PodPhaseMode:        api.PodPhaseModeRunning,
		MaxPodsPerSubject:   1,
		MaxWorkloadsPerPod:  1,
		IncludeRuleMetadata: true,
	}, nil)

	if status.MatchedPods != 1 {
		t.Fatalf("expected running filter + maxPods limit to keep 1 pod, got %d", status.MatchedPods)
	}
	if status.MatchedWorkloads != 1 {
		t.Fatalf("expected maxWorkloads limit to keep 1 workload, got %d", status.MatchedWorkloads)
	}
	assertHasNodeType(t, status.Graph.Nodes, api.GraphNodeTypePodOverflow)
	assertHasNodeType(t, status.Graph.Nodes, api.GraphNodeTypeWorkloadOverflow)
}

func TestQuery_NamespaceScopeStrictFalseKeepsClusterScopedBindings(t *testing.T) {
	snapshot := runtimeSnapshotForTests()
	e := New()

	status := e.Query(snapshot, api.RoleGraphReviewSpec{
		Selector: api.Selector{
			Resources: []string{"pods/exec"},
			Verbs:     []string{"get"},
		},
		NamespaceScope: api.NamespaceScope{
			Namespaces: []string{"team"},
			Strict:     false,
		},
	}, nil)

	if status.MatchedRoles != 1 {
		t.Fatalf("expected cluster-scoped role to remain visible with strict=false, got matchedRoles=%d", status.MatchedRoles)
	}
	if status.MatchedBindings != 1 {
		t.Fatalf("expected cluster-scoped binding to remain visible with strict=false, got matchedBindings=%d", status.MatchedBindings)
	}
}

func TestQuery_NamespaceScopeStrictTrueDropsClusterScopedRoleWithoutNamespacedBindings(t *testing.T) {
	snapshot := runtimeSnapshotForTests()
	e := New()

	status := e.Query(snapshot, api.RoleGraphReviewSpec{
		Selector: api.Selector{
			Resources: []string{"pods/exec"},
			Verbs:     []string{"get"},
		},
		NamespaceScope: api.NamespaceScope{
			Namespaces: []string{"team"},
			Strict:     true,
		},
	}, nil)

	if status.MatchedRoles != 0 {
		t.Fatalf("expected strict namespace scope to drop cluster-scoped role without namespaced bindings, got matchedRoles=%d", status.MatchedRoles)
	}
	if status.MatchedBindings != 0 {
		t.Fatalf("expected strict namespace scope to drop cluster-scoped bindings, got matchedBindings=%d", status.MatchedBindings)
	}
}

func TestQuery_NamespaceScopeStrictTrueKeepsClusterRoleWhenNamespacedBindingMatches(t *testing.T) {
	snapshot := runtimeSnapshotForTests()
	roleRef := indexer.RoleRefKey{Kind: indexer.KindClusterRole, Name: "exec-role"}
	snapshot.BindingsByRoleRef[roleRef] = []*indexer.BindingRecord{
		{
			UID:       types.UID("binding-ns-1"),
			Kind:      indexer.KindRoleBinding,
			Name:      "bind-exec-in-team",
			Namespace: "team",
			RoleRef:   roleRef,
			Subjects:  []rbacv1.Subject{{Kind: indexer.SubjectKindServiceAccount, Namespace: "team", Name: "demo-sa"}},
		},
	}

	e := New()
	status := e.Query(snapshot, api.RoleGraphReviewSpec{
		Selector: api.Selector{
			Resources: []string{"pods/exec"},
			Verbs:     []string{"get"},
		},
		NamespaceScope: api.NamespaceScope{
			Namespaces: []string{"team"},
			Strict:     true,
		},
	}, nil)

	if status.MatchedRoles != 1 {
		t.Fatalf("expected cluster-scoped role to remain when it reaches namespaced binding, got matchedRoles=%d", status.MatchedRoles)
	}
	if status.MatchedBindings != 1 {
		t.Fatalf("expected namespaced binding to remain in strict mode, got matchedBindings=%d", status.MatchedBindings)
	}
	if status.MatchedSubjects != 1 {
		t.Fatalf("expected namespaced subject to remain in strict mode, got matchedSubjects=%d", status.MatchedSubjects)
	}
}

func phantomSnapshotForTests() (*indexer.Snapshot, *indexer.APIDiscoveryCache) {
	snapshot := &indexer.Snapshot{
		BuiltAt:           time.Now(),
		RolesByID:         map[indexer.RoleID]*indexer.RoleRecord{},
		BindingsByRoleRef: map[indexer.RoleRefKey][]*indexer.BindingRecord{},
		RoleIDsByVerb:     map[string]map[indexer.RoleID]struct{}{},
		RoleIDsByResource: map[string]map[indexer.RoleID]struct{}{},
		RoleIDsByAPIGroup: map[string]map[indexer.RoleID]struct{}{},
		AllRoleIDs:        []indexer.RoleID{},
	}

	// Role with a real API group ("") and a phantom group ("custom.metrics.k8s.io").
	role := &indexer.RoleRecord{
		UID:  types.UID("r-phantom"),
		Kind: indexer.KindClusterRole,
		Name: "mixed-role",
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"get"},
			},
			{
				APIGroups: []string{"custom.metrics.k8s.io"},
				Resources: []string{"pods"},
				Verbs:     []string{"get"},
			},
		},
	}
	roleID := indexer.RoleID("clusterrole:mixed-role")
	snapshot.RolesByID[roleID] = role
	snapshot.AllRoleIDs = []indexer.RoleID{roleID}
	snapshot.RoleIDsByAPIGroup[""] = map[indexer.RoleID]struct{}{roleID: {}}
	snapshot.RoleIDsByAPIGroup["custom.metrics.k8s.io"] = map[indexer.RoleID]struct{}{roleID: {}}
	snapshot.RoleIDsByResource["pods"] = map[indexer.RoleID]struct{}{roleID: {}}
	snapshot.RoleIDsByVerb["get"] = map[indexer.RoleID]struct{}{roleID: {}}

	binding := &indexer.BindingRecord{
		UID:      types.UID("b-phantom"),
		Kind:     indexer.KindClusterRoleBinding,
		Name:     "bind-mixed",
		RoleRef:  indexer.RoleRefKey{Kind: indexer.KindClusterRole, Name: "mixed-role"},
		Subjects: []rbacv1.Subject{{Kind: indexer.SubjectKindUser, Name: "alice"}},
	}
	snapshot.BindingsByRoleRef[binding.RoleRef] = []*indexer.BindingRecord{binding}

	// Discovery cache that only knows about core API group.
	discovery := &indexer.APIDiscoveryCache{
		Groups: map[string]struct{}{
			"": {},
		},
		ResourcesByGroup: map[string]map[string]struct{}{
			"": {"pods": {}, "pods/exec": {}, "services": {}, "configmaps": {}},
		},
		AllResources: map[string]struct{}{"pods": {}, "pods/exec": {}, "services": {}, "configmaps": {}},
		AllVerbs:     map[string]struct{}{"get": {}, "list": {}, "create": {}},
		FetchedAt:    time.Now(),
	}

	return snapshot, discovery
}

func TestQuery_PhantomAnnotation(t *testing.T) {
	snapshot, discovery := phantomSnapshotForTests()
	e := New()
	status := e.Query(snapshot, api.RoleGraphReviewSpec{
		Selector: api.Selector{
			Resources: []string{"pods"},
			Verbs:     []string{"get"},
		},
		IncludeRuleMetadata: true,
	}, discovery)

	if status.MatchedRoles != 1 {
		t.Fatalf("expected 1 matched role, got %d", status.MatchedRoles)
	}

	// Check that phantom refs are annotated.
	var phantomCount, realCount int
	for _, node := range status.Graph.Nodes {
		for _, ref := range node.MatchedRuleRefs {
			if ref.Phantom {
				phantomCount++
			} else {
				realCount++
			}
		}
	}
	if phantomCount == 0 {
		t.Fatalf("expected at least one phantom RuleRef")
	}
	if realCount == 0 {
		t.Fatalf("expected at least one real (non-phantom) RuleRef")
	}

	// Check that a warning was emitted for the phantom API group.
	if !contains(status.Warnings, `API group "custom.metrics.k8s.io" referenced in role rules is not installed in the cluster`) {
		t.Fatalf("expected phantom API group warning, got warnings=%v", status.Warnings)
	}
}

func TestQuery_PhantomFilterRemovesPhantomRefs(t *testing.T) {
	snapshot, discovery := phantomSnapshotForTests()
	e := New()
	status := e.Query(snapshot, api.RoleGraphReviewSpec{
		Selector: api.Selector{
			Resources: []string{"pods"},
			Verbs:     []string{"get"},
		},
		FilterPhantomAPIs:   true,
		IncludeRuleMetadata: true,
	}, discovery)

	// Role still matches because the real ref (core group) survives filtering.
	if status.MatchedRoles != 1 {
		t.Fatalf("expected 1 matched role after filtering, got %d", status.MatchedRoles)
	}

	// No phantom refs should remain in the output.
	for _, node := range status.Graph.Nodes {
		for _, ref := range node.MatchedRuleRefs {
			if ref.Phantom {
				t.Fatalf("expected no phantom refs after filtering, found %+v", ref)
			}
		}
	}
	for _, edge := range status.Graph.Edges {
		for _, ref := range edge.RuleRefs {
			if ref.Phantom {
				t.Fatalf("expected no phantom refs in edges after filtering, found %+v", ref)
			}
		}
	}
}

func TestQuery_PhantomFilterExcludesRoleWhenAllRefsPhantom(t *testing.T) {
	snapshot := &indexer.Snapshot{
		BuiltAt:           time.Now(),
		RolesByID:         map[indexer.RoleID]*indexer.RoleRecord{},
		BindingsByRoleRef: map[indexer.RoleRefKey][]*indexer.BindingRecord{},
		RoleIDsByVerb:     map[string]map[indexer.RoleID]struct{}{},
		RoleIDsByResource: map[string]map[indexer.RoleID]struct{}{},
		RoleIDsByAPIGroup: map[string]map[indexer.RoleID]struct{}{},
		AllRoleIDs:        []indexer.RoleID{},
	}

	// Role referencing ONLY a phantom API group.
	role := &indexer.RoleRecord{
		UID:  types.UID("r-all-phantom"),
		Kind: indexer.KindClusterRole,
		Name: "all-phantom-role",
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{"custom.metrics.k8s.io"},
			Resources: []string{"pods"},
			Verbs:     []string{"get"},
		}},
	}
	roleID := indexer.RoleID("clusterrole:all-phantom-role")
	snapshot.RolesByID[roleID] = role
	snapshot.AllRoleIDs = []indexer.RoleID{roleID}
	snapshot.RoleIDsByAPIGroup["custom.metrics.k8s.io"] = map[indexer.RoleID]struct{}{roleID: {}}
	snapshot.RoleIDsByResource["pods"] = map[indexer.RoleID]struct{}{roleID: {}}
	snapshot.RoleIDsByVerb["get"] = map[indexer.RoleID]struct{}{roleID: {}}

	binding := &indexer.BindingRecord{
		UID:      types.UID("b-all-phantom"),
		Kind:     indexer.KindClusterRoleBinding,
		Name:     "bind-all-phantom",
		RoleRef:  indexer.RoleRefKey{Kind: indexer.KindClusterRole, Name: "all-phantom-role"},
		Subjects: []rbacv1.Subject{{Kind: indexer.SubjectKindUser, Name: "bob"}},
	}
	snapshot.BindingsByRoleRef[binding.RoleRef] = []*indexer.BindingRecord{binding}

	discovery := &indexer.APIDiscoveryCache{
		Groups:           map[string]struct{}{"": {}},
		ResourcesByGroup: map[string]map[string]struct{}{"": {"pods": {}}},
		AllResources:     map[string]struct{}{"pods": {}},
		AllVerbs:         map[string]struct{}{"get": {}},
		FetchedAt:        time.Now(),
	}

	e := New()
	status := e.Query(snapshot, api.RoleGraphReviewSpec{
		Selector: api.Selector{
			Resources: []string{"pods"},
			Verbs:     []string{"get"},
		},
		FilterPhantomAPIs: true,
	}, discovery)

	// All refs are phantom → role excluded entirely.
	if status.MatchedRoles != 0 {
		t.Fatalf("expected 0 matched roles when all refs phantom + filter, got %d", status.MatchedRoles)
	}
	if status.MatchedBindings != 0 {
		t.Fatalf("expected 0 matched bindings when all refs phantom + filter, got %d", status.MatchedBindings)
	}
}

func TestQuery_PhantomWildcardNeverPhantom(t *testing.T) {
	snapshot := &indexer.Snapshot{
		BuiltAt:           time.Now(),
		RolesByID:         map[indexer.RoleID]*indexer.RoleRecord{},
		BindingsByRoleRef: map[indexer.RoleRefKey][]*indexer.BindingRecord{},
		RoleIDsByVerb:     map[string]map[indexer.RoleID]struct{}{},
		RoleIDsByResource: map[string]map[indexer.RoleID]struct{}{},
		RoleIDsByAPIGroup: map[string]map[indexer.RoleID]struct{}{},
		AllRoleIDs:        []indexer.RoleID{},
	}

	role := &indexer.RoleRecord{
		UID:  types.UID("r-wildcard"),
		Kind: indexer.KindClusterRole,
		Name: "wildcard-role",
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{"*"},
			Resources: []string{"*"},
			Verbs:     []string{"get"},
		}},
	}
	roleID := indexer.RoleID("clusterrole:wildcard-role")
	snapshot.RolesByID[roleID] = role
	snapshot.AllRoleIDs = []indexer.RoleID{roleID}
	snapshot.RoleIDsByAPIGroup["*"] = map[indexer.RoleID]struct{}{roleID: {}}
	snapshot.RoleIDsByResource["*"] = map[indexer.RoleID]struct{}{roleID: {}}
	snapshot.RoleIDsByVerb["get"] = map[indexer.RoleID]struct{}{roleID: {}}

	binding := &indexer.BindingRecord{
		UID:      types.UID("b-wildcard"),
		Kind:     indexer.KindClusterRoleBinding,
		Name:     "bind-wildcard",
		RoleRef:  indexer.RoleRefKey{Kind: indexer.KindClusterRole, Name: "wildcard-role"},
		Subjects: []rbacv1.Subject{{Kind: indexer.SubjectKindUser, Name: "admin"}},
	}
	snapshot.BindingsByRoleRef[binding.RoleRef] = []*indexer.BindingRecord{binding}

	discovery := &indexer.APIDiscoveryCache{
		Groups:           map[string]struct{}{"": {}},
		ResourcesByGroup: map[string]map[string]struct{}{"": {"pods": {}}},
		AllResources:     map[string]struct{}{"pods": {}},
		AllVerbs:         map[string]struct{}{"get": {}},
		FetchedAt:        time.Now(),
	}

	e := New()
	status := e.Query(snapshot, api.RoleGraphReviewSpec{
		Selector: api.Selector{
			Verbs: []string{"get"},
		},
	}, discovery)

	if status.MatchedRoles != 1 {
		t.Fatalf("expected wildcard role to match, got %d", status.MatchedRoles)
	}

	// Wildcard refs should never be phantom.
	for _, node := range status.Graph.Nodes {
		for _, ref := range node.MatchedRuleRefs {
			if ref.Phantom {
				t.Fatalf("wildcard ref should never be phantom: %+v", ref)
			}
		}
	}
}

func TestQuery_PhantomNilDiscoverySkipsDetection(t *testing.T) {
	snapshot, _ := phantomSnapshotForTests()
	e := New()
	status := e.Query(snapshot, api.RoleGraphReviewSpec{
		Selector: api.Selector{
			Resources: []string{"pods"},
			Verbs:     []string{"get"},
		},
	}, nil)

	// Without discovery, no phantom detection — all refs are non-phantom.
	for _, node := range status.Graph.Nodes {
		for _, ref := range node.MatchedRuleRefs {
			if ref.Phantom {
				t.Fatalf("expected no phantom refs when discovery is nil, found %+v", ref)
			}
		}
	}
}

func TestQuery_PhantomResourceInExistingGroup(t *testing.T) {
	snapshot := &indexer.Snapshot{
		BuiltAt:           time.Now(),
		RolesByID:         map[indexer.RoleID]*indexer.RoleRecord{},
		BindingsByRoleRef: map[indexer.RoleRefKey][]*indexer.BindingRecord{},
		RoleIDsByVerb:     map[string]map[indexer.RoleID]struct{}{},
		RoleIDsByResource: map[string]map[indexer.RoleID]struct{}{},
		RoleIDsByAPIGroup: map[string]map[indexer.RoleID]struct{}{},
		AllRoleIDs:        []indexer.RoleID{},
	}

	// Role references "widgets" in core group — resource doesn't exist.
	role := &indexer.RoleRecord{
		UID:  types.UID("r-bad-resource"),
		Kind: indexer.KindClusterRole,
		Name: "bad-resource-role",
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{""},
			Resources: []string{"widgets"},
			Verbs:     []string{"get"},
		}},
	}
	roleID := indexer.RoleID("clusterrole:bad-resource-role")
	snapshot.RolesByID[roleID] = role
	snapshot.AllRoleIDs = []indexer.RoleID{roleID}
	snapshot.RoleIDsByAPIGroup[""] = map[indexer.RoleID]struct{}{roleID: {}}
	snapshot.RoleIDsByResource["widgets"] = map[indexer.RoleID]struct{}{roleID: {}}
	snapshot.RoleIDsByVerb["get"] = map[indexer.RoleID]struct{}{roleID: {}}

	binding := &indexer.BindingRecord{
		UID:      types.UID("b-bad-resource"),
		Kind:     indexer.KindClusterRoleBinding,
		Name:     "bind-bad-resource",
		RoleRef:  indexer.RoleRefKey{Kind: indexer.KindClusterRole, Name: "bad-resource-role"},
		Subjects: []rbacv1.Subject{{Kind: indexer.SubjectKindUser, Name: "charlie"}},
	}
	snapshot.BindingsByRoleRef[binding.RoleRef] = []*indexer.BindingRecord{binding}

	discovery := &indexer.APIDiscoveryCache{
		Groups:           map[string]struct{}{"": {}},
		ResourcesByGroup: map[string]map[string]struct{}{"": {"pods": {}, "services": {}}},
		AllResources:     map[string]struct{}{"pods": {}, "services": {}},
		AllVerbs:         map[string]struct{}{"get": {}},
		FetchedAt:        time.Now(),
	}

	e := New()
	status := e.Query(snapshot, api.RoleGraphReviewSpec{
		Selector: api.Selector{
			Resources: []string{"widgets"},
			Verbs:     []string{"get"},
		},
		IncludeRuleMetadata: true,
	}, discovery)

	if status.MatchedRoles != 1 {
		t.Fatalf("expected 1 matched role (annotated), got %d", status.MatchedRoles)
	}

	var hasPhantom bool
	for _, node := range status.Graph.Nodes {
		for _, ref := range node.MatchedRuleRefs {
			if ref.Phantom && ref.Resource == "widgets" {
				hasPhantom = true
			}
		}
	}
	if !hasPhantom {
		t.Fatalf("expected phantom ref for resource 'widgets' in core group")
	}

	if !contains(status.Warnings, `resource "widgets" in API group "" is not registered in the cluster`) {
		t.Fatalf("expected phantom resource warning, got warnings=%v", status.Warnings)
	}
}

// discoveryWithVerbs returns a discovery cache with VerbsByGroupResource populated.
func discoveryWithVerbs() *indexer.APIDiscoveryCache {
	return &indexer.APIDiscoveryCache{
		Groups: map[string]struct{}{
			"":     {},
			"apps": {},
		},
		ResourcesByGroup: map[string]map[string]struct{}{
			"":     {"pods": {}, "pods/exec": {}, "services": {}, "configmaps": {}},
			"apps": {"deployments": {}, "replicasets": {}},
		},
		VerbsByGroupResource: map[string]map[string][]string{
			"": {
				"pods":       {"create", "delete", "get", "list", "watch"},
				"pods/exec":  {"create"},
				"services":   {"create", "delete", "get", "list", "update"},
				"configmaps": {"create", "delete", "get", "list", "patch", "update"},
			},
			"apps": {
				"deployments": {"create", "delete", "get", "list", "update"},
				"replicasets": {"create", "delete", "get", "list", "update"},
			},
		},
		AllResources: map[string]struct{}{
			"pods": {}, "pods/exec": {}, "services": {}, "configmaps": {},
			"deployments": {}, "replicasets": {},
		},
		AllVerbs:  map[string]struct{}{"get": {}, "list": {}, "watch": {}, "create": {}, "update": {}, "patch": {}, "delete": {}},
		FetchedAt: time.Now(),
	}
}

func wildcardSnapshotForTests(rules []rbacv1.PolicyRule) (*indexer.Snapshot, *indexer.APIDiscoveryCache) {
	snapshot := &indexer.Snapshot{
		BuiltAt:           time.Now(),
		RolesByID:         map[indexer.RoleID]*indexer.RoleRecord{},
		BindingsByRoleRef: map[indexer.RoleRefKey][]*indexer.BindingRecord{},
		RoleIDsByVerb:     map[string]map[indexer.RoleID]struct{}{},
		RoleIDsByResource: map[string]map[indexer.RoleID]struct{}{},
		RoleIDsByAPIGroup: map[string]map[indexer.RoleID]struct{}{},
		AllRoleIDs:        []indexer.RoleID{},
	}

	role := &indexer.RoleRecord{
		UID:   types.UID("r-wc"),
		Kind:  indexer.KindClusterRole,
		Name:  "wildcard-test-role",
		Rules: rules,
	}
	roleID := indexer.RoleID("clusterrole:wildcard-test-role")
	snapshot.RolesByID[roleID] = role
	snapshot.AllRoleIDs = []indexer.RoleID{roleID}

	for _, rule := range rules {
		for _, g := range rule.APIGroups {
			if snapshot.RoleIDsByAPIGroup[g] == nil {
				snapshot.RoleIDsByAPIGroup[g] = map[indexer.RoleID]struct{}{}
			}
			snapshot.RoleIDsByAPIGroup[g][roleID] = struct{}{}
		}
		for _, r := range rule.Resources {
			if snapshot.RoleIDsByResource[r] == nil {
				snapshot.RoleIDsByResource[r] = map[indexer.RoleID]struct{}{}
			}
			snapshot.RoleIDsByResource[r][roleID] = struct{}{}
		}
		for _, v := range rule.Verbs {
			if snapshot.RoleIDsByVerb[v] == nil {
				snapshot.RoleIDsByVerb[v] = map[indexer.RoleID]struct{}{}
			}
			snapshot.RoleIDsByVerb[v][roleID] = struct{}{}
		}
	}

	binding := &indexer.BindingRecord{
		UID:      types.UID("b-wc"),
		Kind:     indexer.KindClusterRoleBinding,
		Name:     "bind-wildcard-test",
		RoleRef:  indexer.RoleRefKey{Kind: indexer.KindClusterRole, Name: "wildcard-test-role"},
		Subjects: []rbacv1.Subject{{Kind: indexer.SubjectKindUser, Name: "admin"}},
	}
	snapshot.BindingsByRoleRef[binding.RoleRef] = []*indexer.BindingRecord{binding}

	return snapshot, discoveryWithVerbs()
}

func TestQuery_WildcardExpansion_APIGroup(t *testing.T) {
	snapshot, discovery := wildcardSnapshotForTests([]rbacv1.PolicyRule{{
		APIGroups: []string{"*"},
		Resources: []string{"pods"},
		Verbs:     []string{"get"},
	}})

	e := New()
	status := e.Query(snapshot, api.RoleGraphReviewSpec{
		Selector:            api.Selector{Verbs: []string{"get"}},
		IncludeRuleMetadata: true,
	}, discovery)

	if status.MatchedRoles != 1 {
		t.Fatalf("expected 1 matched role, got %d", status.MatchedRoles)
	}

	var expandedRef *api.RuleRef
	for _, node := range status.Graph.Nodes {
		for i := range node.MatchedRuleRefs {
			if node.MatchedRuleRefs[i].APIGroup == "*" {
				expandedRef = &node.MatchedRuleRefs[i]
			}
		}
	}
	if expandedRef == nil {
		t.Fatal("expected wildcard ref with APIGroup=*")
	}
	if len(expandedRef.ExpandedRefs) == 0 {
		t.Fatal("expected ExpandedRefs to be populated for wildcard apiGroup")
	}

	// Only core group has "pods"; apps group doesn't → filtered out.
	if len(expandedRef.ExpandedRefs) != 1 {
		t.Fatalf("expected 1 expanded ref, got %d: %+v", len(expandedRef.ExpandedRefs), expandedRef.ExpandedRefs)
	}
	er := expandedRef.ExpandedRefs[0]
	if er.APIGroup != "" {
		t.Fatalf("expected core group, got %q", er.APIGroup)
	}
	if er.Resource != "pods" {
		t.Fatalf("expected resource=pods, got %q", er.Resource)
	}
	if er.Verb != "get" {
		t.Fatalf("expected verb=get, got %q", er.Verb)
	}
}

func TestQuery_WildcardExpansion_Resource(t *testing.T) {
	snapshot, discovery := wildcardSnapshotForTests([]rbacv1.PolicyRule{{
		APIGroups: []string{""},
		Resources: []string{"*"},
		Verbs:     []string{"get"},
	}})

	e := New()
	status := e.Query(snapshot, api.RoleGraphReviewSpec{
		Selector:            api.Selector{Verbs: []string{"get"}},
		IncludeRuleMetadata: true,
	}, discovery)

	if status.MatchedRoles != 1 {
		t.Fatalf("expected 1 matched role, got %d", status.MatchedRoles)
	}

	var expandedRef *api.RuleRef
	for _, node := range status.Graph.Nodes {
		for i := range node.MatchedRuleRefs {
			if node.MatchedRuleRefs[i].Resource == "*" {
				expandedRef = &node.MatchedRuleRefs[i]
			}
		}
	}
	if expandedRef == nil {
		t.Fatal("expected wildcard ref with Resource=*")
	}
	if len(expandedRef.ExpandedRefs) == 0 {
		t.Fatal("expected ExpandedRefs for wildcard resource")
	}

	// Core group has: pods, pods/exec, services, configmaps.
	// Verb is concrete "get" — pods/exec only supports "create" per discovery,
	// so it is filtered out. Only 3 resources remain.
	resourcesSeen := map[string]bool{}
	for _, er := range expandedRef.ExpandedRefs {
		resourcesSeen[er.Resource] = true
		if er.APIGroup != "" {
			t.Fatalf("expected core group, got %q", er.APIGroup)
		}
		if er.Verb != "get" {
			t.Fatalf("expected verb=get, got %q", er.Verb)
		}
	}
	for _, r := range []string{"pods", "services", "configmaps"} {
		if !resourcesSeen[r] {
			t.Fatalf("expected %q in expanded refs", r)
		}
	}
	if resourcesSeen["pods/exec"] {
		t.Fatal("pods/exec should be filtered out (discovery says it only supports 'create')")
	}
	if len(expandedRef.ExpandedRefs) != 3 {
		t.Fatalf("expected 3 expanded refs (pods/exec filtered), got %d", len(expandedRef.ExpandedRefs))
	}
}

func TestQuery_WildcardExpansion_Verb(t *testing.T) {
	snapshot, discovery := wildcardSnapshotForTests([]rbacv1.PolicyRule{{
		APIGroups: []string{""},
		Resources: []string{"pods"},
		Verbs:     []string{"*"},
	}})

	e := New()
	status := e.Query(snapshot, api.RoleGraphReviewSpec{
		Selector:            api.Selector{Resources: []string{"pods"}},
		IncludeRuleMetadata: true,
	}, discovery)

	if status.MatchedRoles != 1 {
		t.Fatalf("expected 1 matched role, got %d", status.MatchedRoles)
	}

	var expandedRef *api.RuleRef
	for _, node := range status.Graph.Nodes {
		for i := range node.MatchedRuleRefs {
			if node.MatchedRuleRefs[i].Verb == "*" {
				expandedRef = &node.MatchedRuleRefs[i]
			}
		}
	}
	if expandedRef == nil {
		t.Fatal("expected wildcard ref with Verb=*")
	}
	if len(expandedRef.ExpandedRefs) == 0 {
		t.Fatal("expected ExpandedRefs for wildcard verb")
	}

	// pods has verbs: create, delete, get, list, watch
	verbsSeen := map[string]bool{}
	for _, er := range expandedRef.ExpandedRefs {
		verbsSeen[er.Verb] = true
	}
	for _, v := range []string{"create", "delete", "get", "list", "watch"} {
		if !verbsSeen[v] {
			t.Fatalf("expected verb %q in expanded refs", v)
		}
	}
	if len(expandedRef.ExpandedRefs) != 5 {
		t.Fatalf("expected 5 expanded refs (one per verb), got %d", len(expandedRef.ExpandedRefs))
	}
}

func TestQuery_WildcardExpansion_FullWildcard(t *testing.T) {
	snapshot, discovery := wildcardSnapshotForTests([]rbacv1.PolicyRule{{
		APIGroups: []string{"*"},
		Resources: []string{"*"},
		Verbs:     []string{"*"},
	}})

	e := New()
	status := e.Query(snapshot, api.RoleGraphReviewSpec{
		Selector:            api.Selector{Verbs: []string{"get"}},
		IncludeRuleMetadata: true,
	}, discovery)

	if status.MatchedRoles != 1 {
		t.Fatalf("expected 1 matched role, got %d", status.MatchedRoles)
	}

	// The matcher in expand mode resolves verb "*" to the concrete selector verb "get",
	// but keeps apiGroup="*" and resource="*" since selector doesn't constrain them.
	var expandedRef *api.RuleRef
	for _, node := range status.Graph.Nodes {
		for i := range node.MatchedRuleRefs {
			ref := &node.MatchedRuleRefs[i]
			if ref.APIGroup == "*" && ref.Resource == "*" {
				expandedRef = ref
			}
		}
	}
	if expandedRef == nil {
		t.Fatal("expected wildcard ref with APIGroup=* and Resource=*")
	}
	if len(expandedRef.ExpandedRefs) == 0 {
		t.Fatal("expected ExpandedRefs for wildcard ref")
	}

	// Verify we have entries from multiple groups and resources.
	groups := map[string]bool{}
	resources := map[string]bool{}
	for _, er := range expandedRef.ExpandedRefs {
		groups[er.APIGroup] = true
		resources[er.Resource] = true
	}
	if len(groups) < 2 {
		t.Fatalf("expected multiple groups, got %v", groups)
	}
	if len(resources) < 3 {
		t.Fatalf("expected multiple resources, got %v", resources)
	}
}

func TestQuery_WildcardExpansion_NoWildcard(t *testing.T) {
	snapshot, discovery := wildcardSnapshotForTests([]rbacv1.PolicyRule{{
		APIGroups: []string{""},
		Resources: []string{"pods"},
		Verbs:     []string{"get"},
	}})

	e := New()
	status := e.Query(snapshot, api.RoleGraphReviewSpec{
		Selector:            api.Selector{Resources: []string{"pods"}, Verbs: []string{"get"}},
		IncludeRuleMetadata: true,
	}, discovery)

	if status.MatchedRoles != 1 {
		t.Fatalf("expected 1 matched role, got %d", status.MatchedRoles)
	}

	for _, node := range status.Graph.Nodes {
		for _, ref := range node.MatchedRuleRefs {
			if len(ref.ExpandedRefs) > 0 {
				t.Fatalf("expected no ExpandedRefs for non-wildcard ref, got %d", len(ref.ExpandedRefs))
			}
		}
	}
}

func TestQuery_WildcardExpansion_NilDiscovery(t *testing.T) {
	snapshot, _ := wildcardSnapshotForTests([]rbacv1.PolicyRule{{
		APIGroups: []string{"*"},
		Resources: []string{"*"},
		Verbs:     []string{"*"},
	}})

	e := New()
	status := e.Query(snapshot, api.RoleGraphReviewSpec{
		Selector:            api.Selector{Verbs: []string{"get"}},
		IncludeRuleMetadata: true,
	}, nil)

	if status.MatchedRoles != 1 {
		t.Fatalf("expected 1 matched role, got %d", status.MatchedRoles)
	}

	for _, node := range status.Graph.Nodes {
		for _, ref := range node.MatchedRuleRefs {
			if len(ref.ExpandedRefs) > 0 {
				t.Fatal("expected no expansion when discovery is nil")
			}
		}
	}
}

func TestQuery_WildcardExpansion_Cap(t *testing.T) {
	// Build a discovery cache with enough resources to exceed the 2000 cap.
	// The matcher resolves verb "*" to concrete "get" from selector, so each
	// (group, resource) pair produces 1 expanded ref. Need >2000 pairs.
	discovery := discoveryWithVerbs()
	for i := range 210 {
		g := fmt.Sprintf("test-group-%d.example.com", i)
		discovery.Groups[g] = struct{}{}
		discovery.ResourcesByGroup[g] = make(map[string]struct{})
		discovery.VerbsByGroupResource[g] = make(map[string][]string)
		for j := range 10 {
			r := fmt.Sprintf("resource%d", j)
			discovery.ResourcesByGroup[g][r] = struct{}{}
			discovery.VerbsByGroupResource[g][r] = []string{"create", "delete", "get", "list", "patch", "update", "watch"}
		}
	}

	snapshot, _ := wildcardSnapshotForTests([]rbacv1.PolicyRule{{
		APIGroups: []string{"*"},
		Resources: []string{"*"},
		Verbs:     []string{"*"},
	}})

	e := New()
	status := e.Query(snapshot, api.RoleGraphReviewSpec{
		Selector:            api.Selector{Verbs: []string{"get"}},
		IncludeRuleMetadata: true,
	}, discovery)

	if status.MatchedRoles != 1 {
		t.Fatalf("expected 1 matched role, got %d", status.MatchedRoles)
	}

	// The matcher resolves verb "*" to concrete "get" from selector,
	// but apiGroup and resource stay as "*".
	var expandedRef *api.RuleRef
	for _, node := range status.Graph.Nodes {
		for i := range node.MatchedRuleRefs {
			ref := &node.MatchedRuleRefs[i]
			if ref.APIGroup == "*" && ref.Resource == "*" {
				expandedRef = ref
			}
		}
	}
	if expandedRef == nil {
		t.Fatal("expected wildcard ref with APIGroup=* and Resource=*")
	}
	if len(expandedRef.ExpandedRefs) != 2000 {
		t.Fatalf("expected expansion capped at 2000, got %d", len(expandedRef.ExpandedRefs))
	}

	// Should have a truncation warning.
	hasWarning := false
	for _, w := range status.Warnings {
		if strings.Contains(w, "truncated at 2000") {
			hasWarning = true
		}
	}
	if !hasWarning {
		t.Fatalf("expected truncation warning, got warnings=%v", status.Warnings)
	}
}

func runtimeSnapshotForTests() *indexer.Snapshot {
	snapshot := &indexer.Snapshot{
		BuiltAt:               time.Now(),
		RolesByID:             map[indexer.RoleID]*indexer.RoleRecord{},
		BindingsByRoleRef:     map[indexer.RoleRefKey][]*indexer.BindingRecord{},
		AggregatedRoleSources: map[indexer.RoleID][]indexer.RoleID{},
		PodsByServiceAccount:  map[indexer.ServiceAccountKey][]*indexer.PodRecord{},
		WorkloadsByUID:        map[types.UID]*indexer.WorkloadRecord{},
		RoleIDsByVerb:         map[string]map[indexer.RoleID]struct{}{},
		RoleIDsByResource:     map[string]map[indexer.RoleID]struct{}{},
		RoleIDsByAPIGroup:     map[string]map[indexer.RoleID]struct{}{},
		AllRoleIDs:            []indexer.RoleID{},
	}

	role := &indexer.RoleRecord{
		UID:  types.UID("role-1"),
		Kind: indexer.KindClusterRole,
		Name: "exec-role",
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{""},
			Resources: []string{"pods/exec"},
			Verbs:     []string{"get"},
		}},
	}
	roleID := indexer.RoleID("clusterrole:exec-role")
	snapshot.RolesByID[roleID] = role
	snapshot.AllRoleIDs = []indexer.RoleID{roleID}
	snapshot.RoleIDsByAPIGroup[""] = map[indexer.RoleID]struct{}{roleID: {}}
	snapshot.RoleIDsByResource["pods/exec"] = map[indexer.RoleID]struct{}{roleID: {}}
	snapshot.RoleIDsByVerb["get"] = map[indexer.RoleID]struct{}{roleID: {}}

	binding := &indexer.BindingRecord{
		UID:      types.UID("binding-1"),
		Kind:     indexer.KindClusterRoleBinding,
		Name:     "bind-exec",
		RoleRef:  indexer.RoleRefKey{Kind: indexer.KindClusterRole, Name: "exec-role"},
		Subjects: []rbacv1.Subject{{Kind: indexer.SubjectKindServiceAccount, Namespace: "team", Name: "demo-sa"}},
	}
	snapshot.BindingsByRoleRef[binding.RoleRef] = []*indexer.BindingRecord{binding}

	snapshot.PodsByServiceAccount[indexer.ServiceAccountKey{Namespace: "team", Name: "demo-sa"}] = []*indexer.PodRecord{{
		UID:                types.UID("pod-1"),
		Namespace:          "team",
		Name:               "running-pod",
		ServiceAccountName: "demo-sa",
		Phase:              corev1.PodRunning,
		OwnerReferences: []metav1.OwnerReference{{
			APIVersion: "apps/v1",
			Kind:       "ReplicaSet",
			Name:       "demo-rs",
			UID:        types.UID("rs-1"),
			Controller: boolPtr(true),
		}},
	}}

	snapshot.WorkloadsByUID[types.UID("rs-1")] = &indexer.WorkloadRecord{
		UID:        types.UID("rs-1"),
		APIVersion: "apps/v1",
		Kind:       "ReplicaSet",
		Namespace:  "team",
		Name:       "demo-rs",
		OwnerReferences: []metav1.OwnerReference{{
			APIVersion: "apps/v1",
			Kind:       "Deployment",
			Name:       "demo-deploy",
			UID:        types.UID("deploy-1"),
			Controller: boolPtr(true),
		}},
	}
	snapshot.WorkloadsByUID[types.UID("deploy-1")] = &indexer.WorkloadRecord{
		UID:             types.UID("deploy-1"),
		APIVersion:      "apps/v1",
		Kind:            "Deployment",
		Namespace:       "team",
		Name:            "demo-deploy",
		OwnerReferences: nil,
	}

	return snapshot
}

func TestMergeRuleRefs_DedupesWithoutLoss(t *testing.T) {
	existing := []api.RuleRef{
		{
			APIGroup:        "",
			Resource:        "pods",
			Subresource:     "exec",
			Verb:            "get",
			SourceObjectUID: "uid-a",
			SourceRuleIndex: 1,
		},
	}
	incoming := []api.RuleRef{
		{
			APIGroup:        "",
			Resource:        "pods",
			Subresource:     "exec",
			Verb:            "get",
			SourceObjectUID: "uid-a",
			SourceRuleIndex: 1,
		},
		{
			APIGroup:        "",
			Resource:        "pods",
			Subresource:     "exec",
			Verb:            "create",
			SourceObjectUID: "uid-a",
			SourceRuleIndex: 2,
		},
		{
			APIGroup:      "",
			Resource:      "pods",
			Subresource:   "log",
			Verb:          "get",
			ResourceNames: []string{"p1"},
		},
	}

	merged := mergeRuleRefs(existing, incoming)
	if len(merged) != 3 {
		t.Fatalf("expected 3 unique refs, got %d (%#v)", len(merged), merged)
	}
}

func TestAccumulateResourceRows_AggregatesByStructuredKey(t *testing.T) {
	rows := make(map[resourceRowKey]*resourceAccumulator)
	roleA := indexer.RoleID("clusterrole:role-a")
	roleB := indexer.RoleID("clusterrole:role-b")

	rbacRef := api.RuleRef{
		APIGroup:    "*",
		Resource:    "pods",
		Subresource: "exec",
		Verb:        "get",
	}
	nonResourceRef := api.RuleRef{
		Verb:            "get",
		NonResourceURLs: []string{"/healthz"},
	}

	accumulateResourceRowsInto(rows, []api.RuleRef{rbacRef}, roleA, "binding:a", "subject:a")
	accumulateResourceRowsInto(rows, []api.RuleRef{rbacRef}, roleA, "binding:a", "subject:a")
	accumulateResourceRowsInto(rows, []api.RuleRef{rbacRef}, roleB, "binding:b", "subject:b")
	accumulateResourceRowsInto(rows, []api.RuleRef{nonResourceRef}, roleA, "", "")

	collapsed := collapseResourceRows(rows)
	if len(collapsed) != 2 {
		t.Fatalf("expected 2 rows, got %d", len(collapsed))
	}

	var rbacRow *api.ResourceMapRow
	var nonResourceRow *api.ResourceMapRow
	for i := range collapsed {
		row := collapsed[i]
		if row.Resource == "pods/exec" && row.Verb == "get" {
			rbacRow = &row

			continue
		}
		if row.Resource == "/healthz" && row.Verb == "get" {
			nonResourceRow = &row
		}
	}

	if rbacRow == nil {
		t.Fatalf("expected pods/exec row in collapsed output: %#v", collapsed)
	}
	if rbacRow.RoleCount != 2 || rbacRow.BindingCount != 2 || rbacRow.SubjectCount != 2 {
		t.Fatalf("unexpected pods/exec counts: %#v", rbacRow)
	}
	if nonResourceRow == nil {
		t.Fatalf("expected non-resource row in collapsed output: %#v", collapsed)
	}
	if nonResourceRow.RoleCount != 1 || nonResourceRow.BindingCount != 0 || nonResourceRow.SubjectCount != 0 {
		t.Fatalf("unexpected non-resource counts: %#v", nonResourceRow)
	}
}

// statusToV1alpha1 converts an internal RoleGraphReviewStatus to v1alpha1
// for JSON serialization in golden tests (the golden files test the JSON wire format).
func statusToV1alpha1(t *testing.T, in api.RoleGraphReviewStatus) v1alpha1.RoleGraphReviewStatus {
	t.Helper()
	var out v1alpha1.RoleGraphReviewStatus
	if err := v1alpha1.Convert_rbacgraph_RoleGraphReviewStatus_To_v1alpha1_RoleGraphReviewStatus(&in, &out, nil); err != nil {
		t.Fatalf("convert status to v1alpha1: %v", err)
	}

	return out
}

func TestQuery_GoldenJSONContracts(t *testing.T) {
	t.Parallel()
	update := os.Getenv("UPDATE_GOLDEN") == "1"
	engine := New()

	testCases := []struct {
		name     string
		snapshot *indexer.Snapshot
		spec     api.RoleGraphReviewSpec
	}{
		{
			name:     "basic-rbac",
			snapshot: basicSnapshotForGolden(),
			spec: api.RoleGraphReviewSpec{
				Selector: api.Selector{
					APIGroups: []string{""},
					Resources: []string{"pods/exec"},
					Verbs:     []string{"create"},
				},
				MatchMode:           api.MatchModeAny,
				IncludeRuleMetadata: true,
			},
		},
		{
			name:     "runtime-chain",
			snapshot: runtimeSnapshotForTests(),
			spec: api.RoleGraphReviewSpec{
				Selector: api.Selector{
					Resources: []string{"pods/exec"},
					Verbs:     []string{"get"},
				},
				IncludeRuleMetadata: true,
				IncludePods:         true,
				IncludeWorkloads:    true,
				PodPhaseMode:        api.PodPhaseModeActive,
			},
		},
		{
			name:     "aggregated-rbac",
			snapshot: aggregatedSnapshotForGolden(),
			spec: api.RoleGraphReviewSpec{
				Selector: api.Selector{
					APIGroups: []string{""},
					Resources: []string{"pods/exec"},
					Verbs:     []string{"get"},
				},
				MatchMode:           api.MatchModeAny,
				IncludeRuleMetadata: true,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			status := engine.Query(tc.snapshot, tc.spec, nil)

			// Convert internal status → v1alpha1 for JSON marshaling (golden
			// files test the wire format clients see, which has JSON tags).
			v1Status := statusToV1alpha1(t, status)

			got, err := json.MarshalIndent(v1Status, "", "  ")
			if err != nil {
				t.Fatalf("marshal status: %v", err)
			}
			got = append(got, '\n')

			goldenPath := filepath.Join("testdata", tc.name+".golden.json")
			if update {
				if writeErr := os.WriteFile(goldenPath, got, 0o644); writeErr != nil {
					t.Fatalf("write golden %s: %v", goldenPath, writeErr)
				}
			}

			want, err := os.ReadFile(goldenPath)
			if err != nil {
				t.Fatalf("read golden %s: %v", goldenPath, err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("golden mismatch for %s\n--- got ---\n%s\n--- want ---\n%s", tc.name, string(got), string(want))
			}
		})
	}
}

func basicSnapshotForGolden() *indexer.Snapshot {
	snapshot := &indexer.Snapshot{
		BuiltAt:           time.Now(),
		RolesByID:         map[indexer.RoleID]*indexer.RoleRecord{},
		BindingsByRoleRef: map[indexer.RoleRefKey][]*indexer.BindingRecord{},
		RoleIDsByVerb:     map[string]map[indexer.RoleID]struct{}{},
		RoleIDsByResource: map[string]map[indexer.RoleID]struct{}{},
		RoleIDsByAPIGroup: map[string]map[indexer.RoleID]struct{}{},
		AllRoleIDs:        []indexer.RoleID{},
	}

	role := &indexer.RoleRecord{
		UID:       types.UID("r1"),
		Kind:      indexer.KindClusterRole,
		Name:      "exec-role",
		Namespace: "",
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{""},
			Resources: []string{"pods/exec"},
			Verbs:     []string{"create"},
		}},
	}
	roleID := indexer.RoleID("clusterrole:exec-role")
	snapshot.RolesByID[roleID] = role
	snapshot.AllRoleIDs = []indexer.RoleID{roleID}
	snapshot.RoleIDsByAPIGroup[""] = map[indexer.RoleID]struct{}{roleID: {}}
	snapshot.RoleIDsByResource["pods/exec"] = map[indexer.RoleID]struct{}{roleID: {}}
	snapshot.RoleIDsByVerb["create"] = map[indexer.RoleID]struct{}{roleID: {}}

	binding := &indexer.BindingRecord{
		UID:      types.UID("b1"),
		Kind:     indexer.KindClusterRoleBinding,
		Name:     "bind-exec",
		RoleRef:  indexer.RoleRefKey{Kind: indexer.KindClusterRole, Name: "exec-role"},
		Subjects: []rbacv1.Subject{{Kind: indexer.SubjectKindUser, Name: "alice"}},
	}
	snapshot.BindingsByRoleRef[binding.RoleRef] = []*indexer.BindingRecord{binding}

	return snapshot
}

func aggregatedSnapshotForGolden() *indexer.Snapshot {
	snapshot := &indexer.Snapshot{
		BuiltAt:               time.Now(),
		RolesByID:             map[indexer.RoleID]*indexer.RoleRecord{},
		BindingsByRoleRef:     map[indexer.RoleRefKey][]*indexer.BindingRecord{},
		AggregatedRoleSources: map[indexer.RoleID][]indexer.RoleID{},
		RoleIDsByVerb:         map[string]map[indexer.RoleID]struct{}{},
		RoleIDsByResource:     map[string]map[indexer.RoleID]struct{}{},
		RoleIDsByAPIGroup:     map[string]map[indexer.RoleID]struct{}{},
		AllRoleIDs:            []indexer.RoleID{},
	}

	sourceRole := &indexer.RoleRecord{
		UID:  types.UID("src"),
		Kind: indexer.KindClusterRole,
		Name: "aggregate-to-edit-source",
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{""},
			Resources: []string{"pods/exec"},
			Verbs:     []string{"get"},
		}},
	}
	aggregatedRole := &indexer.RoleRecord{
		UID:  types.UID("agg"),
		Kind: indexer.KindClusterRole,
		Name: "edit",
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{""},
			Resources: []string{"pods/exec"},
			Verbs:     []string{"get"},
		}},
	}

	sourceRoleID := indexer.RoleID("clusterrole:aggregate-to-edit-source")
	aggregatedRoleID := indexer.RoleID("clusterrole:edit")
	snapshot.RolesByID[sourceRoleID] = sourceRole
	snapshot.RolesByID[aggregatedRoleID] = aggregatedRole
	snapshot.AllRoleIDs = []indexer.RoleID{aggregatedRoleID}
	snapshot.AggregatedRoleSources[aggregatedRoleID] = []indexer.RoleID{sourceRoleID}
	snapshot.RoleIDsByAPIGroup[""] = map[indexer.RoleID]struct{}{aggregatedRoleID: {}}
	snapshot.RoleIDsByResource["pods/exec"] = map[indexer.RoleID]struct{}{aggregatedRoleID: {}}
	snapshot.RoleIDsByVerb["get"] = map[indexer.RoleID]struct{}{aggregatedRoleID: {}}

	binding := &indexer.BindingRecord{
		UID:      types.UID("b1"),
		Kind:     indexer.KindClusterRoleBinding,
		Name:     "bind-edit",
		RoleRef:  indexer.RoleRefKey{Kind: indexer.KindClusterRole, Name: "edit"},
		Subjects: []rbacv1.Subject{{Kind: indexer.SubjectKindUser, Name: "bob"}},
	}
	snapshot.BindingsByRoleRef[binding.RoleRef] = []*indexer.BindingRecord{binding}

	return snapshot
}

func boolPtr(v bool) *bool {
	return &v
}

func assertHasNodeType(t *testing.T, nodes []api.GraphNode, nodeType api.GraphNodeType) {
	t.Helper()
	for _, node := range nodes {
		if node.Type == nodeType {
			return
		}
	}
	t.Fatalf("expected node type %q to be present", nodeType)
}

func assertHasEdgeType(t *testing.T, edges []api.GraphEdge, edgeType api.GraphEdgeType) {
	t.Helper()
	for _, edge := range edges {
		if edge.Type == edgeType {
			return
		}
	}
	t.Fatalf("expected edge type %q to be present", edgeType)
}

func contains(values []string, expected string) bool {
	return slices.Contains(values, expected)
}
