package engine

import (
	"encoding/json"
	"testing"
	"time"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/types"

	api "k8s-rbac-engine/pkg/apis/rbacgraph"
	"k8s-rbac-engine/pkg/indexer"
)

// Documentation test: dumps a SubjectPermissionsView Status as JSON to show
// wildcard expansion. Run with `go test -v -run TestDemo_ReverseWildcardExpansion`.
func TestDemo_ReverseWildcardExpansion(t *testing.T) {
	snapshot := buildClusterAdminLikeSnapshot()
	discovery := buildSmallDiscovery()

	e := New()
	status := e.QuerySubjectPermissions(snapshot, api.SubjectPermissionsViewSpec{
		Subject: api.SubjectRef{Kind: api.SubjectKindUser, Name: "alice"},
	}, discovery)

	out, _ := json.MarshalIndent(status, "", "  ")
	t.Logf("\n=== SubjectPermissionsView Status (wildcard expansion ENABLED) ===\n%s\n", string(out))

	// Also demonstrate that grants are concrete after expansion.
	if len(status.Grants) <= 1 {
		t.Errorf("expected expanded grants (>1), got %d — expansion not wired correctly", len(status.Grants))
	}
	for _, g := range status.Grants {
		if g.APIGroup == "*" || g.Resource == "*" || g.Verb == "*" {
			t.Errorf("found unexpanded wildcard in grant after expansion: %+v", g)
		}
	}
}

// buildClusterAdminLikeSnapshot: one */*/* ClusterRole bound to User alice.
func buildClusterAdminLikeSnapshot() *indexer.Snapshot {
	s := &indexer.Snapshot{
		BuiltAt:           time.Now(),
		RolesByID:         map[indexer.RoleID]*indexer.RoleRecord{},
		BindingsByRoleRef: map[indexer.RoleRefKey][]*indexer.BindingRecord{},
		BindingsBySubject: map[indexer.SubjectKey][]*indexer.BindingRecord{},
		RoleIDsByVerb:     map[string]map[indexer.RoleID]struct{}{},
		RoleIDsByResource: map[string]map[indexer.RoleID]struct{}{},
		RoleIDsByAPIGroup: map[string]map[indexer.RoleID]struct{}{},
		AllRoleIDs:        []indexer.RoleID{},
	}

	role := &indexer.RoleRecord{
		UID:  types.UID("cr-admin"),
		Kind: indexer.KindClusterRole,
		Name: "cluster-admin",
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{"*"},
			Resources: []string{"*"},
			Verbs:     []string{"*"},
		}},
	}
	id := indexer.RecID(indexer.KindClusterRole, "", "cluster-admin")
	s.RolesByID[id] = role
	s.AllRoleIDs = append(s.AllRoleIDs, id)

	binding := &indexer.BindingRecord{
		UID:      types.UID("crb-admin"),
		Kind:     indexer.KindClusterRoleBinding,
		Name:     "alice-admin",
		RoleRef:  indexer.RoleRefKey{Kind: indexer.KindClusterRole, Name: "cluster-admin"},
		Subjects: []rbacv1.Subject{{Kind: indexer.SubjectKindUser, Name: "alice"}},
	}
	s.BindingsByRoleRef[binding.RoleRef] = []*indexer.BindingRecord{binding}
	s.BindingsBySubject[indexer.SubjectKey{Kind: indexer.SubjectKindUser, Name: "alice"}] = []*indexer.BindingRecord{binding}

	return s
}

// buildSmallDiscovery returns a discovery cache with 3 apiGroups and a few
// resources each.
func buildSmallDiscovery() *indexer.APIDiscoveryCache {
	return &indexer.APIDiscoveryCache{
		Groups: map[string]struct{}{"": {}, "apps": {}, "rbac.authorization.k8s.io": {}},
		ResourcesByGroup: map[string]map[string]struct{}{
			"": {
				"pods":       {},
				"pods/exec":  {},
				"secrets":    {},
				"configmaps": {},
			},
			"apps": {
				"deployments": {},
				"replicasets": {},
			},
			"rbac.authorization.k8s.io": {
				"roles":        {},
				"rolebindings": {},
			},
		},
		VerbsByGroupResource: map[string]map[string][]string{
			"": {
				"pods":       {"get", "list", "watch", "create", "delete"},
				"pods/exec":  {"create", "get"},
				"secrets":    {"get", "list", "watch"},
				"configmaps": {"get", "list", "watch", "create"},
			},
			"apps": {
				"deployments": {"get", "list", "watch", "create", "patch", "delete"},
				"replicasets": {"get", "list", "watch"},
			},
			"rbac.authorization.k8s.io": {
				"roles":        {"get", "list", "create"},
				"rolebindings": {"get", "list", "create"},
			},
		},
		AllResources: map[string]struct{}{
			"pods": {}, "pods/exec": {}, "secrets": {}, "configmaps": {},
			"deployments": {}, "replicasets": {},
			"roles": {}, "rolebindings": {},
		},
		AllVerbs: map[string]struct{}{
			"get": {}, "list": {}, "watch": {}, "create": {}, "patch": {}, "delete": {},
		},
		FetchedAt: time.Now(),
	}
}
