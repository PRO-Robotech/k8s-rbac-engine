package indexer_test

import (
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/types"

	"k8s-rbac-engine/internal/authz"
	"k8s-rbac-engine/pkg/indexer"
)

func buildTestSnapshot() *indexer.Snapshot {
	s := indexer.NewEmptySnapshotForTest()

	// ClusterRole: cluster-admin
	crID := indexer.RecID(indexer.KindClusterRole, "", "cluster-admin")
	s.RolesByID[crID] = &indexer.RoleRecord{
		UID:       types.UID("cr-1"),
		Kind:      indexer.KindClusterRole,
		Namespace: "",
		Name:      "cluster-admin",
		Rules: []rbacv1.PolicyRule{
			{Verbs: []string{"*"}, APIGroups: []string{"*"}, Resources: []string{"*"}},
		},
		RuleCount: 1,
	}
	s.AllRoleIDs = append(s.AllRoleIDs, crID)
	indexer.IndexRoleTokensForTest(s, crID, s.RolesByID[crID].Rules)

	// Role: ns-a/read-pods
	roleAID := indexer.RecID(indexer.KindRole, "ns-a", "read-pods")
	s.RolesByID[roleAID] = &indexer.RoleRecord{
		UID:       types.UID("role-a-1"),
		Kind:      indexer.KindRole,
		Namespace: "ns-a",
		Name:      "read-pods",
		Rules: []rbacv1.PolicyRule{
			{Verbs: []string{"get", "list"}, APIGroups: []string{""}, Resources: []string{"pods"}},
		},
		RuleCount: 1,
	}
	s.AllRoleIDs = append(s.AllRoleIDs, roleAID)
	indexer.IndexRoleTokensForTest(s, roleAID, s.RolesByID[roleAID].Rules)

	// Role: ns-b/write-configmaps
	roleBID := indexer.RecID(indexer.KindRole, "ns-b", "write-configmaps")
	s.RolesByID[roleBID] = &indexer.RoleRecord{
		UID:       types.UID("role-b-1"),
		Kind:      indexer.KindRole,
		Namespace: "ns-b",
		Name:      "write-configmaps",
		Rules: []rbacv1.PolicyRule{
			{Verbs: []string{"create", "update"}, APIGroups: []string{""}, Resources: []string{"configmaps"}},
		},
		RuleCount: 1,
	}
	s.AllRoleIDs = append(s.AllRoleIDs, roleBID)
	indexer.IndexRoleTokensForTest(s, roleBID, s.RolesByID[roleBID].Rules)

	// ClusterRoleBinding for cluster-admin
	crbKey := indexer.RoleRefKey{Kind: indexer.KindClusterRole, Name: "cluster-admin"}
	s.BindingsByRoleRef[crbKey] = []*indexer.BindingRecord{
		{
			UID:     types.UID("crb-1"),
			Kind:    indexer.KindClusterRoleBinding,
			Name:    "admin-binding",
			RoleRef: crbKey,
			Subjects: []rbacv1.Subject{
				{Kind: indexer.SubjectKindUser, Name: "admin"},
			},
		},
	}

	// RoleBinding in ns-a
	rbAKey := indexer.RoleRefKey{Kind: indexer.KindRole, Namespace: "ns-a", Name: "read-pods"}
	s.BindingsByRoleRef[rbAKey] = []*indexer.BindingRecord{
		{
			UID:       types.UID("rb-a-1"),
			Kind:      indexer.KindRoleBinding,
			Namespace: "ns-a",
			Name:      "read-pods-binding",
			RoleRef:   rbAKey,
			Subjects: []rbacv1.Subject{
				{Kind: indexer.SubjectKindServiceAccount, Namespace: "ns-a", Name: "sa-1"},
			},
		},
	}

	// RoleBinding in ns-b
	rbBKey := indexer.RoleRefKey{Kind: indexer.KindRole, Namespace: "ns-b", Name: "write-configmaps"}
	s.BindingsByRoleRef[rbBKey] = []*indexer.BindingRecord{
		{
			UID:       types.UID("rb-b-1"),
			Kind:      indexer.KindRoleBinding,
			Namespace: "ns-b",
			Name:      "write-configmaps-binding",
			RoleRef:   rbBKey,
			Subjects: []rbacv1.Subject{
				{Kind: indexer.SubjectKindServiceAccount, Namespace: "ns-b", Name: "sa-2"},
			},
		},
	}

	// Pods in ns-a and ns-b
	s.PodsByServiceAccount[indexer.ServiceAccountKey{Namespace: "ns-a", Name: "sa-1"}] = []*indexer.PodRecord{
		{UID: types.UID("pod-a-1"), Namespace: "ns-a", Name: "pod-a"},
	}
	s.PodsByServiceAccount[indexer.ServiceAccountKey{Namespace: "ns-b", Name: "sa-2"}] = []*indexer.PodRecord{
		{UID: types.UID("pod-b-1"), Namespace: "ns-b", Name: "pod-b"},
	}

	// Workloads
	s.WorkloadsByUID[types.UID("wl-a")] = &indexer.WorkloadRecord{
		UID: types.UID("wl-a"), Kind: "Deployment", Namespace: "ns-a", Name: "deploy-a",
	}
	s.WorkloadsByUID[types.UID("wl-b")] = &indexer.WorkloadRecord{
		UID: types.UID("wl-b"), Kind: "Deployment", Namespace: "ns-b", Name: "deploy-b",
	}

	// Aggregation: cluster-admin aggregates from "view" ClusterRole
	viewID := indexer.RecID(indexer.KindClusterRole, "", "view")
	s.RolesByID[viewID] = &indexer.RoleRecord{
		UID:  types.UID("cr-view"),
		Kind: indexer.KindClusterRole,
		Name: "view",
		Rules: []rbacv1.PolicyRule{
			{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"pods"}},
		},
		RuleCount: 1,
	}
	s.AllRoleIDs = append(s.AllRoleIDs, viewID)
	indexer.IndexRoleTokensForTest(s, viewID, s.RolesByID[viewID].Rules)
	s.AggregatedRoleSources[crID] = []indexer.RoleID{viewID}

	s.Warnings = []string{"test warning"}
	s.KnownGaps = []string{"test gap"}

	indexer.SortSnapshotForTest(s)

	return s
}

func TestScoped_Unrestricted(t *testing.T) {
	s := buildTestSnapshot()
	scope := &authz.AccessScope{
		CanListClusterRoles:        true,
		CanListClusterRoleBindings: true,
		CanListRoles:               true,
		CanListRoleBindings:        true,
		CanListPods:                true,
		CanListWorkloads:           true,
	}

	result := indexer.Scoped(s, scope)
	if result != s {
		t.Fatal("expected same pointer for unrestricted scope")
	}
}

func TestScoped_NoClusterRoles(t *testing.T) {
	s := buildTestSnapshot()
	scope := &authz.AccessScope{
		CanListClusterRoles:        false, // deny ClusterRoles
		CanListClusterRoleBindings: true,
		CanListRoles:               true,
		CanListRoleBindings:        true,
		CanListPods:                true,
		CanListWorkloads:           true,
	}

	result := indexer.Scoped(s, scope)
	if result == s {
		t.Fatal("expected different pointer for restricted scope")
	}

	// ClusterRoles should be removed.
	for id, rec := range result.RolesByID {
		if rec.Kind == indexer.KindClusterRole {
			t.Errorf("expected no ClusterRoles, found %s", id)
		}
	}

	// Namespaced roles should remain.
	nsARoleID := indexer.RecID(indexer.KindRole, "ns-a", "read-pods")
	if _, ok := result.RolesByID[nsARoleID]; !ok {
		t.Error("expected ns-a role to remain")
	}
}

func TestScoped_OnlyNamespaceA(t *testing.T) {
	s := buildTestSnapshot()
	scope := &authz.AccessScope{
		CanListClusterRoles:        true,
		CanListClusterRoleBindings: true,
		AllowedRoleNamespaces:      map[string]struct{}{"ns-a": {}},
		AllowedBindingNamespaces:   map[string]struct{}{"ns-a": {}},
		AllowedPodNamespaces:       map[string]struct{}{"ns-a": {}},
		AllowedWorkloadNamespaces:  map[string]struct{}{"ns-a": {}},
	}

	result := indexer.Scoped(s, scope)

	// ns-a role should be present.
	nsARoleID := indexer.RecID(indexer.KindRole, "ns-a", "read-pods")
	if _, ok := result.RolesByID[nsARoleID]; !ok {
		t.Error("expected ns-a role to be present")
	}

	// ns-b role should be filtered out.
	nsBRoleID := indexer.RecID(indexer.KindRole, "ns-b", "write-configmaps")
	if _, ok := result.RolesByID[nsBRoleID]; ok {
		t.Error("expected ns-b role to be filtered out")
	}

	// ns-b bindings should be filtered out.
	rbBKey := indexer.RoleRefKey{Kind: indexer.KindRole, Namespace: "ns-b", Name: "write-configmaps"}
	if bindings, ok := result.BindingsByRoleRef[rbBKey]; ok && len(bindings) > 0 {
		t.Error("expected ns-b bindings to be filtered out")
	}

	// ns-b pods should be filtered out.
	for _, pods := range result.PodsByServiceAccount {
		for _, p := range pods {
			if p.Namespace == "ns-b" {
				t.Errorf("expected no ns-b pods, found %s", p.Name)
			}
		}
	}

	// ns-b workloads should be filtered out.
	for _, w := range result.WorkloadsByUID {
		if w.Namespace == "ns-b" {
			t.Errorf("expected no ns-b workloads, found %s", w.Name)
		}
	}
}

func TestScoped_TokenIndexes(t *testing.T) {
	s := buildTestSnapshot()
	scope := &authz.AccessScope{
		CanListClusterRoles:        false, // deny ClusterRoles
		CanListClusterRoleBindings: true,
		AllowedRoleNamespaces:      map[string]struct{}{"ns-a": {}},
		AllowedBindingNamespaces:   map[string]struct{}{"ns-a": {}},
		CanListPods:                true,
		CanListWorkloads:           true,
	}

	result := indexer.Scoped(s, scope)

	// The "configmaps" resource token should not be in the index (ns-b filtered out).
	if roles, ok := result.RoleIDsByResource["configmaps"]; ok && len(roles) > 0 {
		t.Error("expected configmaps resource not in index after ns-b filtered out")
	}

	// The "pods" resource token should still be present (ns-a role has it).
	podsRoles, ok := result.RoleIDsByResource["pods"]
	if !ok || len(podsRoles) == 0 {
		t.Error("expected pods resource in index from ns-a role")
	}

	// The "*" token should not be present (ClusterRoles filtered out).
	starRoles, ok := result.RoleIDsByResource["*"]
	if ok && len(starRoles) > 0 {
		t.Error("expected * resource not in index after ClusterRoles filtered out")
	}

	// AllRoleIDs should be sorted and consistent.
	for i := 1; i < len(result.AllRoleIDs); i++ {
		if result.AllRoleIDs[i] < result.AllRoleIDs[i-1] {
			t.Error("AllRoleIDs not sorted")

			break
		}
	}

	// AllRoleIDs count should match RolesByID.
	if len(result.AllRoleIDs) != len(result.RolesByID) {
		t.Errorf("AllRoleIDs count (%d) != RolesByID count (%d)", len(result.AllRoleIDs), len(result.RolesByID))
	}
}

func TestScoped_AggregatedSources(t *testing.T) {
	s := buildTestSnapshot()

	// Deny ClusterRoles — aggregation sources should be cleaned up.
	scope := &authz.AccessScope{
		CanListClusterRoles:        false,
		CanListClusterRoleBindings: true,
		CanListRoles:               true,
		CanListRoleBindings:        true,
		CanListPods:                true,
		CanListWorkloads:           true,
	}

	result := indexer.Scoped(s, scope)

	if len(result.AggregatedRoleSources) != 0 {
		t.Errorf("expected no aggregated role sources after ClusterRoles filtered, got %d", len(result.AggregatedRoleSources))
	}
}

func TestScoped_WarningsAndGaps(t *testing.T) {
	s := buildTestSnapshot()
	scope := &authz.AccessScope{
		CanListClusterRoles:        false,
		CanListClusterRoleBindings: true,
		CanListRoles:               true,
		CanListRoleBindings:        true,
		CanListPods:                true,
		CanListWorkloads:           true,
	}

	result := indexer.Scoped(s, scope)

	if len(result.Warnings) != 1 || result.Warnings[0] != "test warning" {
		t.Errorf("expected cloned warnings, got %v", result.Warnings)
	}
	if len(result.KnownGaps) != 1 || result.KnownGaps[0] != "test gap" {
		t.Errorf("expected cloned known gaps, got %v", result.KnownGaps)
	}

	// Modifying result warnings should not affect original.
	result.Warnings = append(result.Warnings, "new warning")
	if len(s.Warnings) != 1 {
		t.Error("expected original warnings to be unmodified")
	}
}

func TestScoped_EmptySnapshot(t *testing.T) {
	s := indexer.NewEmptySnapshotForTest()
	scope := &authz.AccessScope{
		AllowedRoleNamespaces: map[string]struct{}{"ns-a": {}},
	}

	result := indexer.Scoped(s, scope)
	if len(result.RolesByID) != 0 {
		t.Error("expected empty snapshot to remain empty")
	}
	if len(result.AllRoleIDs) != 0 {
		t.Error("expected no AllRoleIDs")
	}
}
