// Package v1alpha1 — scheme registration for the rbacreports.in-cloud.io API group.
//
// This file mirrors the layout produced by `kubebuilder` so the standard
// AddToScheme call works in cmd/rbac-engine main wiring and in tests via
// `client/fake.NewClientBuilder().WithScheme(...)`.

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// GroupName is the API group for all rbacreports types.
const GroupName = "rbacreports.in-cloud.io"

// GroupVersion is the GroupVersion used to register these objects.
var GroupVersion = schema.GroupVersion{Group: GroupName, Version: "v1alpha1"}

// SchemeBuilder collects all types into a runtime.Scheme.
var SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)

// AddToScheme registers the rbacreports types with a runtime.Scheme.
var AddToScheme = SchemeBuilder.AddToScheme

func addKnownTypes(s *runtime.Scheme) error {
	s.AddKnownTypes(GroupVersion,
		&RbacPolicy{},
		&RbacPolicyList{},
		&RbacReport{},
		&RbacReportList{},
		&ClusterRbacReport{},
		&ClusterRbacReportList{},
	)
	metav1.AddToGroupVersion(s, GroupVersion)

	return nil
}
