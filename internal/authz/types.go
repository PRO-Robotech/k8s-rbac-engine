package authz

import (
	"context"

	"k8s.io/apiserver/pkg/authentication/user"

	"k8s-rbac-engine/pkg/indexer"
)

// ScopeResolver determines what RBAC objects a caller may list.
type ScopeResolver interface {
	Resolve(ctx context.Context, userInfo user.Info, namespacesToCheck []string) (*AccessScope, error)
}

type AccessScope struct {
	CanListClusterRoles        bool
	CanListClusterRoleBindings bool

	CanListRoles          bool
	AllowedRoleNamespaces map[string]struct{}

	CanListRoleBindings      bool
	AllowedBindingNamespaces map[string]struct{}

	CanListPods          bool
	AllowedPodNamespaces map[string]struct{}

	CanListWorkloads          bool
	AllowedWorkloadNamespaces map[string]struct{}

	Warnings []string
}

// IsUnrestricted returns true when every resource type is visible cluster-wide.
func (s *AccessScope) IsUnrestricted() bool {
	return s.CanListClusterRoles &&
		s.CanListClusterRoleBindings &&
		s.CanListRoles && s.AllowedRoleNamespaces == nil &&
		s.CanListRoleBindings && s.AllowedBindingNamespaces == nil &&
		s.CanListPods && s.AllowedPodNamespaces == nil &&
		s.CanListWorkloads && s.AllowedWorkloadNamespaces == nil
}

func (s *AccessScope) AllowRole(namespace string) bool {
	return allowNS(namespace, s.CanListClusterRoles, s.CanListRoles, s.AllowedRoleNamespaces)
}

func (s *AccessScope) AllowBinding(namespace string) bool {
	return allowNS(namespace, s.CanListClusterRoleBindings, s.CanListRoleBindings, s.AllowedBindingNamespaces)
}

func (s *AccessScope) AllowPod(namespace string) bool {
	return allowNS(namespace, false, s.CanListPods, s.AllowedPodNamespaces)
}

func (s *AccessScope) AllowWorkload(namespace string) bool {
	return allowNS(namespace, false, s.CanListWorkloads, s.AllowedWorkloadNamespaces)
}

func allowNS(ns string, clusterWide, allNS bool, allowed map[string]struct{}) bool {
	if ns == "" {
		return clusterWide
	}
	if allNS {
		return true
	}
	if allowed == nil {
		return false
	}
	_, ok := allowed[ns]

	return ok
}

var _ indexer.Scope = (*AccessScope)(nil)
