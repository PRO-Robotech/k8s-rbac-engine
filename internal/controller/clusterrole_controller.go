package controller

import (
	"context"

	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"k8s-rbac-engine/pkg/apis/rbacreports/v1alpha1"
	"k8s-rbac-engine/pkg/policyengine"
	"k8s-rbac-engine/pkg/report"
)

// ClusterRoleReconciler watches ClusterRole and produces ClusterRbacReport.
type ClusterRoleReconciler struct {
	Client client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterroles,verbs=get;list;watch
// +kubebuilder:rbac:groups=rbacreports.in-cloud.io,resources=clusterrbacreports,verbs=get;list;watch;create;update;patch;delete

// Reconcile implements reconcile.Reconciler.
func (r *ClusterRoleReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var role rbacv1.ClusterRole
	if err := r.Client.Get(ctx, req.NamespacedName, &role); err != nil {
		if apierrors.IsNotFound(err) {
			logger.V(1).Info("ClusterRole not found; relying on GC for owned ClusterRbacReport")

			return emptyResult, nil
		}

		return emptyResult, err
	}

	policies, err := listAllPolicies(ctx, r.Client)
	if err != nil {
		return emptyResult, err
	}

	record := roleRecordFromClusterRole(&role)
	findings := policyengine.Evaluate(record, policies)
	desired := report.BuildClusterRbacReport(record, findings)

	if err := upsertClusterRbacReport(ctx, r.Client, desired); err != nil {
		return emptyResult, err
	}

	return emptyResult, nil
}

// SetupWithManager wires up the controller. The shape mirrors
// RoleReconciler.SetupWithManager but with the cluster-scoped types.
func (r *ClusterRoleReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("rbacreports-clusterrole").
		For(&rbacv1.ClusterRole{}).
		Owns(&v1alpha1.ClusterRbacReport{}).
		Watches(
			&v1alpha1.RbacPolicy{},
			handler.EnqueueRequestsFromMapFunc(r.policyFanOut),
		).
		Complete(r)
}

func (r *ClusterRoleReconciler) policyFanOut(ctx context.Context, _ client.Object) []reconcile.Request {
	return enqueueAllClusterRoles(ctx, r.Client)
}
