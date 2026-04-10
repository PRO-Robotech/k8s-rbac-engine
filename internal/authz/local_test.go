package authz

import (
	"context"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apiserver/pkg/authentication/user"

	"k8s-rbac-engine/pkg/indexer"
)

// helper to build a minimal snapshot with RBAC data.
func newTestSnapshot() *indexer.Snapshot {
	return &indexer.Snapshot{
		RolesByID:         make(map[indexer.RoleID]*indexer.RoleRecord),
		BindingsByRoleRef: make(map[indexer.RoleRefKey][]*indexer.BindingRecord),
	}
}

func snapshotFn(s *indexer.Snapshot) func() *indexer.Snapshot {
	return func() *indexer.Snapshot { return s }
}

// allNamespaces is the namespace list passed to Resolve for per-namespace checks.
var allNamespaces = []string{"ns-a", "ns-b", "ns-c"}

func TestLocalResolver_ClusterAdmin(t *testing.T) {
	snap := newTestSnapshot()

	// ClusterRole "cluster-admin" with wildcard everything.
	crID := indexer.RecID("ClusterRole", "", "cluster-admin")
	snap.RolesByID[crID] = &indexer.RoleRecord{
		UID:  types.UID("cr-1"),
		Kind: "ClusterRole", Name: "cluster-admin",
		Rules: []rbacv1.PolicyRule{
			{Verbs: []string{"*"}, APIGroups: []string{"*"}, Resources: []string{"*"}},
		},
	}

	// ClusterRoleBinding granting cluster-admin to user "admin".
	key := indexer.RoleRefKey{Kind: "ClusterRole", Name: "cluster-admin"}
	snap.BindingsByRoleRef[key] = []*indexer.BindingRecord{
		{
			UID: types.UID("crb-1"), Kind: "ClusterRoleBinding", Name: "admin-binding",
			RoleRef:  key,
			Subjects: []rbacv1.Subject{{Kind: "User", Name: "admin"}},
		},
	}

	lr := NewLocalResolver(snapshotFn(snap))
	scope, err := lr.Resolve(context.Background(), &user.DefaultInfo{Name: "admin"}, allNamespaces)
	if err != nil {
		t.Fatal(err)
	}

	if !scope.IsUnrestricted() {
		t.Error("expected unrestricted scope for cluster-admin")
	}
}

func TestLocalResolver_NoAccess(t *testing.T) {
	snap := newTestSnapshot()

	// ClusterRole exists but no binding for this user.
	crID := indexer.RecID("ClusterRole", "", "reader")
	snap.RolesByID[crID] = &indexer.RoleRecord{
		UID:  types.UID("cr-1"),
		Kind: "ClusterRole", Name: "reader",
		Rules: []rbacv1.PolicyRule{
			{Verbs: []string{"list"}, APIGroups: []string{"*"}, Resources: []string{"*"}},
		},
	}
	key := indexer.RoleRefKey{Kind: "ClusterRole", Name: "reader"}
	snap.BindingsByRoleRef[key] = []*indexer.BindingRecord{
		{
			UID: types.UID("crb-1"), Kind: "ClusterRoleBinding", Name: "reader-binding",
			RoleRef:  key,
			Subjects: []rbacv1.Subject{{Kind: "User", Name: "other-user"}},
		},
	}

	lr := NewLocalResolver(snapshotFn(snap))
	scope, err := lr.Resolve(context.Background(), &user.DefaultInfo{Name: "nobody"}, allNamespaces)
	if err != nil {
		t.Fatal(err)
	}

	if scope.CanListClusterRoles || scope.CanListClusterRoleBindings ||
		scope.CanListRoles || scope.CanListRoleBindings ||
		scope.CanListPods || scope.CanListWorkloads {
		t.Error("expected no cluster-wide access for unknown user")
	}
}

func TestLocalResolver_NamespaceScoped(t *testing.T) {
	snap := newTestSnapshot()

	// Role in ns-a granting list on roles, rolebindings, pods, deployments.
	roleID := indexer.RecID("Role", "ns-a", "ns-reader")
	snap.RolesByID[roleID] = &indexer.RoleRecord{
		UID: types.UID("r-1"), Kind: "Role", Namespace: "ns-a", Name: "ns-reader",
		Rules: []rbacv1.PolicyRule{
			{Verbs: []string{"list"}, APIGroups: []string{"rbac.authorization.k8s.io"}, Resources: []string{"roles", "rolebindings"}},
			{Verbs: []string{"list"}, APIGroups: []string{""}, Resources: []string{"pods"}},
			{Verbs: []string{"list"}, APIGroups: []string{"apps"}, Resources: []string{"deployments"}},
		},
	}
	key := indexer.RoleRefKey{Kind: "Role", Namespace: "ns-a", Name: "ns-reader"}
	snap.BindingsByRoleRef[key] = []*indexer.BindingRecord{
		{
			UID: types.UID("rb-1"), Kind: "RoleBinding", Namespace: "ns-a", Name: "ns-reader-binding",
			RoleRef:  key,
			Subjects: []rbacv1.Subject{{Kind: "User", Name: "dev"}},
		},
	}

	lr := NewLocalResolver(snapshotFn(snap))
	scope, err := lr.Resolve(context.Background(), &user.DefaultInfo{Name: "dev"}, allNamespaces)
	if err != nil {
		t.Fatal(err)
	}

	// Cluster-wide should be denied.
	if scope.CanListClusterRoles || scope.CanListClusterRoleBindings {
		t.Error("expected no cluster-wide access")
	}
	if scope.CanListRoles || scope.CanListRoleBindings || scope.CanListPods || scope.CanListWorkloads {
		t.Error("expected no cluster-wide list access for namespaced role")
	}

	// ns-a should be allowed.
	if _, ok := scope.AllowedRoleNamespaces["ns-a"]; !ok {
		t.Error("expected ns-a in AllowedRoleNamespaces")
	}
	if _, ok := scope.AllowedBindingNamespaces["ns-a"]; !ok {
		t.Error("expected ns-a in AllowedBindingNamespaces")
	}
	if _, ok := scope.AllowedPodNamespaces["ns-a"]; !ok {
		t.Error("expected ns-a in AllowedPodNamespaces")
	}
	if _, ok := scope.AllowedWorkloadNamespaces["ns-a"]; !ok {
		t.Error("expected ns-a in AllowedWorkloadNamespaces")
	}

	// ns-b should not be allowed.
	if _, ok := scope.AllowedRoleNamespaces["ns-b"]; ok {
		t.Error("expected ns-b NOT in AllowedRoleNamespaces")
	}
}

func TestLocalResolver_GroupMatching(t *testing.T) {
	snap := newTestSnapshot()

	crID := indexer.RecID("ClusterRole", "", "group-reader")
	snap.RolesByID[crID] = &indexer.RoleRecord{
		UID: types.UID("cr-1"), Kind: "ClusterRole", Name: "group-reader",
		Rules: []rbacv1.PolicyRule{
			{Verbs: []string{"list"}, APIGroups: []string{"rbac.authorization.k8s.io"}, Resources: []string{"clusterroles"}},
		},
	}
	key := indexer.RoleRefKey{Kind: "ClusterRole", Name: "group-reader"}
	snap.BindingsByRoleRef[key] = []*indexer.BindingRecord{
		{
			UID: types.UID("crb-1"), Kind: "ClusterRoleBinding", Name: "group-binding",
			RoleRef:  key,
			Subjects: []rbacv1.Subject{{Kind: "Group", Name: "developers"}},
		},
	}

	lr := NewLocalResolver(snapshotFn(snap))
	scope, err := lr.Resolve(context.Background(), &user.DefaultInfo{
		Name:   "dev-user",
		Groups: []string{"developers", "system:authenticated"},
	}, allNamespaces)
	if err != nil {
		t.Fatal(err)
	}

	if !scope.CanListClusterRoles {
		t.Error("expected cluster-wide clusterroles access via group binding")
	}
	// Other resources should not be granted.
	if scope.CanListClusterRoleBindings || scope.CanListPods {
		t.Error("expected no access for ungranted resources")
	}
}

func TestLocalResolver_ServiceAccountMatching(t *testing.T) {
	snap := newTestSnapshot()

	crID := indexer.RecID("ClusterRole", "", "pod-reader")
	snap.RolesByID[crID] = &indexer.RoleRecord{
		UID: types.UID("cr-1"), Kind: "ClusterRole", Name: "pod-reader",
		Rules: []rbacv1.PolicyRule{
			{Verbs: []string{"list"}, APIGroups: []string{""}, Resources: []string{"pods"}},
		},
	}
	key := indexer.RoleRefKey{Kind: "ClusterRole", Name: "pod-reader"}
	snap.BindingsByRoleRef[key] = []*indexer.BindingRecord{
		{
			UID: types.UID("crb-1"), Kind: "ClusterRoleBinding", Name: "sa-binding",
			RoleRef: key,
			Subjects: []rbacv1.Subject{
				{Kind: "ServiceAccount", Namespace: "kube-system", Name: "my-sa"},
			},
		},
	}

	lr := NewLocalResolver(snapshotFn(snap))
	scope, err := lr.Resolve(context.Background(), &user.DefaultInfo{
		Name: "system:serviceaccount:kube-system:my-sa",
	}, allNamespaces)
	if err != nil {
		t.Fatal(err)
	}

	if !scope.CanListPods {
		t.Error("expected cluster-wide pods access via SA binding")
	}
}

func TestLocalResolver_WildcardVerb(t *testing.T) {
	snap := newTestSnapshot()

	// Role with verb "*" should match "list".
	crID := indexer.RecID("ClusterRole", "", "star-verb")
	snap.RolesByID[crID] = &indexer.RoleRecord{
		UID: types.UID("cr-1"), Kind: "ClusterRole", Name: "star-verb",
		Rules: []rbacv1.PolicyRule{
			{Verbs: []string{"*"}, APIGroups: []string{""}, Resources: []string{"pods"}},
		},
	}
	key := indexer.RoleRefKey{Kind: "ClusterRole", Name: "star-verb"}
	snap.BindingsByRoleRef[key] = []*indexer.BindingRecord{
		{
			UID: types.UID("crb-1"), Kind: "ClusterRoleBinding", Name: "star-binding",
			RoleRef:  key,
			Subjects: []rbacv1.Subject{{Kind: "User", Name: "user1"}},
		},
	}

	lr := NewLocalResolver(snapshotFn(snap))
	scope, err := lr.Resolve(context.Background(), &user.DefaultInfo{Name: "user1"}, allNamespaces)
	if err != nil {
		t.Fatal(err)
	}

	if !scope.CanListPods {
		t.Error("expected pods access via wildcard verb")
	}
}

func TestLocalResolver_WildcardResourceAndGroup(t *testing.T) {
	snap := newTestSnapshot()

	crID := indexer.RecID("ClusterRole", "", "star-all")
	snap.RolesByID[crID] = &indexer.RoleRecord{
		UID: types.UID("cr-1"), Kind: "ClusterRole", Name: "star-all",
		Rules: []rbacv1.PolicyRule{
			{Verbs: []string{"list"}, APIGroups: []string{"*"}, Resources: []string{"*"}},
		},
	}
	key := indexer.RoleRefKey{Kind: "ClusterRole", Name: "star-all"}
	snap.BindingsByRoleRef[key] = []*indexer.BindingRecord{
		{
			UID: types.UID("crb-1"), Kind: "ClusterRoleBinding", Name: "star-binding",
			RoleRef:  key,
			Subjects: []rbacv1.Subject{{Kind: "User", Name: "user1"}},
		},
	}

	lr := NewLocalResolver(snapshotFn(snap))
	scope, err := lr.Resolve(context.Background(), &user.DefaultInfo{Name: "user1"}, allNamespaces)
	if err != nil {
		t.Fatal(err)
	}

	if !scope.IsUnrestricted() {
		t.Error("expected unrestricted scope for wildcard resource+group")
	}
}

func TestLocalResolver_RoleBindingToClusterRole(t *testing.T) {
	snap := newTestSnapshot()

	// ClusterRole "view" with list on all 6 resources.
	crID := indexer.RecID("ClusterRole", "", "view")
	snap.RolesByID[crID] = &indexer.RoleRecord{
		UID: types.UID("cr-1"), Kind: "ClusterRole", Name: "view",
		Rules: []rbacv1.PolicyRule{
			{Verbs: []string{"list"}, APIGroups: []string{"rbac.authorization.k8s.io"}, Resources: []string{"roles", "rolebindings", "clusterroles", "clusterrolebindings"}},
			{Verbs: []string{"list"}, APIGroups: []string{""}, Resources: []string{"pods"}},
			{Verbs: []string{"list"}, APIGroups: []string{"apps"}, Resources: []string{"deployments"}},
		},
	}

	// RoleBinding in ns-a referencing ClusterRole "view".
	// RoleRefKey for ClusterRole has Namespace="" (the role is cluster-scoped).
	key := indexer.RoleRefKey{Kind: "ClusterRole", Name: "view"}
	snap.BindingsByRoleRef[key] = []*indexer.BindingRecord{
		{
			UID: types.UID("rb-1"), Kind: "RoleBinding", Namespace: "ns-a", Name: "view-in-ns-a",
			RoleRef:  key,
			Subjects: []rbacv1.Subject{{Kind: "User", Name: "dev"}},
		},
	}

	lr := NewLocalResolver(snapshotFn(snap))
	scope, err := lr.Resolve(context.Background(), &user.DefaultInfo{Name: "dev"}, allNamespaces)
	if err != nil {
		t.Fatal(err)
	}

	// Cluster-scoped resources should NOT be granted (RoleBinding can't grant cluster-wide).
	if scope.CanListClusterRoles || scope.CanListClusterRoleBindings {
		t.Error("RoleBinding should not grant cluster-wide access to cluster-scoped resources")
	}

	// Namespace-scoped resources should be granted only in ns-a.
	if scope.CanListRoles {
		t.Error("expected no cluster-wide roles access")
	}
	if _, ok := scope.AllowedRoleNamespaces["ns-a"]; !ok {
		t.Error("expected ns-a in AllowedRoleNamespaces")
	}
	if _, ok := scope.AllowedPodNamespaces["ns-a"]; !ok {
		t.Error("expected ns-a in AllowedPodNamespaces")
	}
	if _, ok := scope.AllowedWorkloadNamespaces["ns-a"]; !ok {
		t.Error("expected ns-a in AllowedWorkloadNamespaces")
	}

	// ns-b should not be allowed.
	if _, ok := scope.AllowedRoleNamespaces["ns-b"]; ok {
		t.Error("expected ns-b NOT in AllowedRoleNamespaces")
	}
}

func TestLocalResolver_NilSnapshot(t *testing.T) {
	lr := NewLocalResolver(func() *indexer.Snapshot { return nil })
	_, err := lr.Resolve(context.Background(), &user.DefaultInfo{Name: "user"}, nil)
	if err == nil {
		t.Error("expected error for nil snapshot")
	}
}

func TestLocalResolver_VerbMismatch(t *testing.T) {
	snap := newTestSnapshot()

	// Role only has "get" verb, not "list".
	crID := indexer.RecID("ClusterRole", "", "getter")
	snap.RolesByID[crID] = &indexer.RoleRecord{
		UID: types.UID("cr-1"), Kind: "ClusterRole", Name: "getter",
		Rules: []rbacv1.PolicyRule{
			{Verbs: []string{"get"}, APIGroups: []string{"*"}, Resources: []string{"*"}},
		},
	}
	key := indexer.RoleRefKey{Kind: "ClusterRole", Name: "getter"}
	snap.BindingsByRoleRef[key] = []*indexer.BindingRecord{
		{
			UID: types.UID("crb-1"), Kind: "ClusterRoleBinding", Name: "getter-binding",
			RoleRef:  key,
			Subjects: []rbacv1.Subject{{Kind: "User", Name: "user1"}},
		},
	}

	lr := NewLocalResolver(snapshotFn(snap))
	scope, err := lr.Resolve(context.Background(), &user.DefaultInfo{Name: "user1"}, allNamespaces)
	if err != nil {
		t.Fatal(err)
	}

	// "get" verb should not match "list".
	if scope.CanListClusterRoles || scope.CanListPods || scope.CanListWorkloads {
		t.Error("expected no access when only 'get' verb is granted")
	}
}

func TestLocalResolver_MultipleBindings(t *testing.T) {
	snap := newTestSnapshot()

	// Two ClusterRoles, each granting list on different resources.
	cr1ID := indexer.RecID("ClusterRole", "", "pods-lister")
	snap.RolesByID[cr1ID] = &indexer.RoleRecord{
		UID: types.UID("cr-1"), Kind: "ClusterRole", Name: "pods-lister",
		Rules: []rbacv1.PolicyRule{
			{Verbs: []string{"list"}, APIGroups: []string{""}, Resources: []string{"pods"}},
		},
	}
	cr2ID := indexer.RecID("ClusterRole", "", "rbac-lister")
	snap.RolesByID[cr2ID] = &indexer.RoleRecord{
		UID: types.UID("cr-2"), Kind: "ClusterRole", Name: "rbac-lister",
		Rules: []rbacv1.PolicyRule{
			{Verbs: []string{"list"}, APIGroups: []string{"rbac.authorization.k8s.io"}, Resources: []string{"clusterroles", "clusterrolebindings"}},
		},
	}

	key1 := indexer.RoleRefKey{Kind: "ClusterRole", Name: "pods-lister"}
	snap.BindingsByRoleRef[key1] = []*indexer.BindingRecord{
		{
			UID: types.UID("crb-1"), Kind: "ClusterRoleBinding", Name: "pods-binding",
			RoleRef:  key1,
			Subjects: []rbacv1.Subject{{Kind: "User", Name: "multi-user"}},
		},
	}
	key2 := indexer.RoleRefKey{Kind: "ClusterRole", Name: "rbac-lister"}
	snap.BindingsByRoleRef[key2] = []*indexer.BindingRecord{
		{
			UID: types.UID("crb-2"), Kind: "ClusterRoleBinding", Name: "rbac-binding",
			RoleRef:  key2,
			Subjects: []rbacv1.Subject{{Kind: "User", Name: "multi-user"}},
		},
	}

	lr := NewLocalResolver(snapshotFn(snap))
	scope, err := lr.Resolve(context.Background(), &user.DefaultInfo{Name: "multi-user"}, allNamespaces)
	if err != nil {
		t.Fatal(err)
	}

	if !scope.CanListPods {
		t.Error("expected pods access from first binding")
	}
	if !scope.CanListClusterRoles {
		t.Error("expected clusterroles access from second binding")
	}
	if !scope.CanListClusterRoleBindings {
		t.Error("expected clusterrolebindings access from second binding")
	}
	// Resources not granted should be denied.
	if scope.CanListWorkloads {
		t.Error("expected no workloads access")
	}
}
