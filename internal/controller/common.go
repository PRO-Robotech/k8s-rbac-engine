// Package controller hosts the reconcilers that translate Role and ClusterRole
// events into RbacReport and ClusterRbacReport objects.
package controller

import (
	"context"

	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"k8s-rbac-engine/pkg/apis/rbacreports/v1alpha1"
	idx "k8s-rbac-engine/pkg/indexer"
)

// listAllPolicies fetches every RbacPolicy in the cluster.
func listAllPolicies(ctx context.Context, c client.Client) ([]v1alpha1.RbacPolicy, error) {
	var list v1alpha1.RbacPolicyList
	if err := c.List(ctx, &list); err != nil {
		return nil, err
	}

	return list.Items, nil
}

// roleRecordFromRole adapts a rbacv1.Role into the indexer.RoleRecord shape
// expected by policyengine.Evaluate.
func roleRecordFromRole(role *rbacv1.Role) *idx.RoleRecord {
	return &idx.RoleRecord{
		UID:         role.UID,
		Kind:        v1alpha1.KindRole,
		Namespace:   role.Namespace,
		Name:        role.Name,
		Labels:      role.Labels,
		Annotations: role.Annotations,
		Rules:       role.Rules,
		RuleCount:   len(role.Rules),
	}
}

// roleRecordFromClusterRole adapts a rbacv1.ClusterRole into the indexer's
// RoleRecord shape.
func roleRecordFromClusterRole(role *rbacv1.ClusterRole) *idx.RoleRecord {
	return &idx.RoleRecord{
		UID:         role.UID,
		Kind:        v1alpha1.KindClusterRole,
		Name:        role.Name,
		Labels:      role.Labels,
		Annotations: role.Annotations,
		Rules:       role.Rules,
		RuleCount:   len(role.Rules),
	}
}

// upsertRbacReport creates or updates an RbacReport in place.
func upsertRbacReport(ctx context.Context, c client.Client, desired *v1alpha1.RbacReport) error {
	logger := log.FromContext(ctx)

	var existing v1alpha1.RbacReport
	key := types.NamespacedName{Namespace: desired.Namespace, Name: desired.Name}
	err := c.Get(ctx, key, &existing)
	if apierrors.IsNotFound(err) {
		logger.V(1).Info("creating RbacReport", "name", desired.Name, "namespace", desired.Namespace)

		return c.Create(ctx, desired)
	}
	if err != nil {
		return err
	}

	existing.Labels = desired.Labels
	existing.OwnerReferences = desired.OwnerReferences
	existing.Spec = desired.Spec
	existing.Report = desired.Report
	logger.V(1).Info("updating RbacReport", "name", desired.Name, "namespace", desired.Namespace)

	return c.Update(ctx, &existing)
}

// upsertClusterRbacReport is the cluster-scoped equivalent of upsertRbacReport.
func upsertClusterRbacReport(ctx context.Context, c client.Client, desired *v1alpha1.ClusterRbacReport) error {
	logger := log.FromContext(ctx)

	var existing v1alpha1.ClusterRbacReport
	key := types.NamespacedName{Name: desired.Name}
	err := c.Get(ctx, key, &existing)
	if apierrors.IsNotFound(err) {
		logger.V(1).Info("creating ClusterRbacReport", "name", desired.Name)

		return c.Create(ctx, desired)
	}
	if err != nil {
		return err
	}

	existing.Labels = desired.Labels
	existing.OwnerReferences = desired.OwnerReferences
	existing.Spec = desired.Spec
	existing.Report = desired.Report
	logger.V(1).Info("updating ClusterRbacReport", "name", desired.Name)

	return c.Update(ctx, &existing)
}

func enqueueAllRoles(ctx context.Context, c client.Client) []reconcile.Request {
	logger := log.FromContext(ctx)

	var list rbacv1.RoleList
	if err := c.List(ctx, &list); err != nil {
		logger.Error(err, "listing Role objects for policy fan-out")

		return nil
	}
	requests := make([]reconcile.Request, len(list.Items))
	for i := range list.Items {
		requests[i] = reconcile.Request{
			NamespacedName: types.NamespacedName{
				Namespace: list.Items[i].Namespace,
				Name:      list.Items[i].Name,
			},
		}
	}
	logger.V(1).Info("policy change fanned out", "kind", v1alpha1.KindRole, "count", len(requests))

	return requests
}

// enqueueAllClusterRoles is the cluster-scoped equivalent of enqueueAllRoles.
func enqueueAllClusterRoles(ctx context.Context, c client.Client) []reconcile.Request {
	logger := log.FromContext(ctx)

	var list rbacv1.ClusterRoleList
	if err := c.List(ctx, &list); err != nil {
		logger.Error(err, "listing ClusterRole objects for policy fan-out")

		return nil
	}
	requests := make([]reconcile.Request, len(list.Items))
	for i := range list.Items {
		requests[i] = reconcile.Request{
			NamespacedName: types.NamespacedName{Name: list.Items[i].Name},
		}
	}
	logger.V(1).Info("policy change fanned out", "kind", v1alpha1.KindClusterRole, "count", len(requests))

	return requests
}

// emptyResult is a typed alias to keep Reconcile signatures readable.
var emptyResult = ctrl.Result{}
