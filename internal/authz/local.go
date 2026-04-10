package authz

import (
	"context"
	"errors"
	"fmt"
	"slices"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apiserver/pkg/authentication/user"

	"k8s-rbac-engine/pkg/indexer"
)

const (
	idxClusterRoles        = 0
	idxClusterRoleBindings = 1
	idxRoles               = 2
	idxRoleBindings        = 3
	idxPods                = 4
	idxDeployments         = 5
	numChecks              = 6
)

type resourceCheck struct {
	resource string
	apiGroup string
}

var knownChecks = []resourceCheck{
	{resource: "clusterroles", apiGroup: "rbac.authorization.k8s.io"},
	{resource: "clusterrolebindings", apiGroup: "rbac.authorization.k8s.io"},
	{resource: "roles", apiGroup: "rbac.authorization.k8s.io"},
	{resource: "rolebindings", apiGroup: "rbac.authorization.k8s.io"},
	{resource: "pods", apiGroup: ""},
	{resource: "deployments", apiGroup: "apps"},
}

type grantSet struct {
	clusterWide [numChecks]bool
	namespaced  [numChecks]map[string]struct{}
}

func (g *grantSet) markClusterWide(idx int) {
	g.clusterWide[idx] = true
}

func (g *grantSet) markNamespace(idx int, ns string) {
	if g.clusterWide[idx] {
		return // already unrestricted
	}
	if g.namespaced[idx] == nil {
		g.namespaced[idx] = make(map[string]struct{})
	}
	g.namespaced[idx][ns] = struct{}{}
}

// LocalResolver evaluates RBAC permissions in-memory using the indexer snapshot.
type LocalResolver struct {
	snapshotFn func() *indexer.Snapshot
}

func NewLocalResolver(snapshotFn func() *indexer.Snapshot) *LocalResolver {
	return &LocalResolver{snapshotFn: snapshotFn}
}

func (lr *LocalResolver) Resolve(_ context.Context, userInfo user.Info, namespacesToCheck []string) (*AccessScope, error) {
	snap := lr.snapshotFn()
	if snap == nil {
		return nil, errors.New("snapshot not available")
	}

	gs := lr.collectGrants(snap, userInfo)

	return lr.buildScope(gs, namespacesToCheck), nil
}

func (lr *LocalResolver) collectGrants(snap *indexer.Snapshot, userInfo user.Info) *grantSet {
	gs := &grantSet{}

	for roleRefKey, bindings := range snap.BindingsByRoleRef {
		roleID := indexer.RecID(roleRefKey.Kind, roleRefKey.Namespace, roleRefKey.Name)
		role, ok := snap.RolesByID[roleID]
		if !ok {
			continue
		}

		for _, binding := range bindings {
			if !subjectMatches(userInfo, binding.Subjects) {
				continue
			}
			applyRuleGrants(gs, role.Rules, binding.Namespace)
		}
	}

	return gs
}

func applyRuleGrants(gs *grantSet, rules []rbacv1.PolicyRule, bindingNamespace string) {
	for _, rule := range rules {
		if !verbAllows(rule.Verbs, "list") {
			continue
		}
		for i, check := range knownChecks {
			if !ruleCovers(rule, check.resource, check.apiGroup) {
				continue
			}
			if bindingNamespace == "" {
				gs.markClusterWide(i)
			} else {
				gs.markNamespace(i, bindingNamespace)
			}
		}
	}
}

func (lr *LocalResolver) buildScope(gs *grantSet, namespacesToCheck []string) *AccessScope {
	scope := &AccessScope{}

	scope.CanListClusterRoles = gs.clusterWide[idxClusterRoles]
	scope.CanListClusterRoleBindings = gs.clusterWide[idxClusterRoleBindings]

	scope.CanListRoles = gs.clusterWide[idxRoles]
	if !scope.CanListRoles {
		scope.AllowedRoleNamespaces = filterNamespaces(gs, idxRoles, namespacesToCheck)
	}

	scope.CanListRoleBindings = gs.clusterWide[idxRoleBindings]
	if !scope.CanListRoleBindings {
		scope.AllowedBindingNamespaces = filterNamespaces(gs, idxRoleBindings, namespacesToCheck)
	}

	scope.CanListPods = gs.clusterWide[idxPods]
	if !scope.CanListPods {
		scope.AllowedPodNamespaces = filterNamespaces(gs, idxPods, namespacesToCheck)
	}

	scope.CanListWorkloads = gs.clusterWide[idxDeployments]
	if !scope.CanListWorkloads {
		scope.AllowedWorkloadNamespaces = filterNamespaces(gs, idxDeployments, namespacesToCheck)
	}

	return scope
}

func filterNamespaces(gs *grantSet, idx int, namespacesToCheck []string) map[string]struct{} {
	if gs.namespaced[idx] == nil {
		return make(map[string]struct{})
	}
	out := make(map[string]struct{})
	for _, ns := range namespacesToCheck {
		if _, ok := gs.namespaced[idx][ns]; ok {
			out[ns] = struct{}{}
		}
	}

	return out
}

func subjectMatches(userInfo user.Info, subjects []rbacv1.Subject) bool {
	for _, subj := range subjects {
		switch subj.Kind {
		case "User":
			if subj.Name == userInfo.GetName() {
				return true
			}
		case "Group":
			if slices.Contains(userInfo.GetGroups(), subj.Name) {
				return true
			}
		case "ServiceAccount":
			saUsername := fmt.Sprintf("system:serviceaccount:%s:%s", subj.Namespace, subj.Name)
			if saUsername == userInfo.GetName() {
				return true
			}
		}
	}

	return false
}

func verbAllows(verbs []string, target string) bool {
	for _, v := range verbs {
		if v == target || v == "*" {
			return true
		}
	}

	return false
}

func ruleCovers(rule rbacv1.PolicyRule, resource, apiGroup string) bool {
	resourceMatch := false
	for _, r := range rule.Resources {
		if r == resource || r == "*" {
			resourceMatch = true

			break
		}
	}
	if !resourceMatch {
		return false
	}

	for _, g := range rule.APIGroups {
		if g == apiGroup || g == "*" {
			return true
		}
	}

	return false
}
