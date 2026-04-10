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

// RoleReconciler watches Role and produces RbacReport.
type RoleReconciler struct {
	Client client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=roles,verbs=get;list;watch
// +kubebuilder:rbac:groups=rbacreports.in-cloud.io,resources=rbacpolicies,verbs=get;list;watch
// +kubebuilder:rbac:groups=rbacreports.in-cloud.io,resources=rbacreports,verbs=get;list;watch;create;update;patch;delete

// Reconcile implements reconcile.Reconciler.
func (r *RoleReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	// controller-runtime injects controller/name/namespace/reconcileID
	// into the logger automatically via context. We just retrieve it.
	logger := log.FromContext(ctx)

	var role rbacv1.Role
	if err := r.Client.Get(ctx, req.NamespacedName, &role); err != nil {
		if apierrors.IsNotFound(err) {
			// Role was deleted: GC handles RbacReport via ownerReference.
			logger.V(1).Info("Role not found; relying on GC for owned RbacReport")

			return emptyResult, nil
		}

		return emptyResult, err
	}

	policies, err := listAllPolicies(ctx, r.Client)
	if err != nil {
		return emptyResult, err
	}

	record := roleRecordFromRole(&role)
	findings := policyengine.Evaluate(record, policies)
	desired := report.BuildRbacReport(record, findings)

	if err := upsertRbacReport(ctx, r.Client, desired); err != nil {
		return emptyResult, err
	}

	return emptyResult, nil
}

// SetupWithManager wires up the controller.
func (r *RoleReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("rbacreports-role").
		For(&rbacv1.Role{}).
		Owns(&v1alpha1.RbacReport{}).
		Watches(
			&v1alpha1.RbacPolicy{},
			handler.EnqueueRequestsFromMapFunc(r.policyFanOut),
		).
		Complete(r)
}

func (r *RoleReconciler) policyFanOut(ctx context.Context, _ client.Object) []reconcile.Request {
	return enqueueAllRoles(ctx, r.Client)
}
