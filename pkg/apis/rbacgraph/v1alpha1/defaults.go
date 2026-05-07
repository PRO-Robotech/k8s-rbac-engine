package v1alpha1

import "k8s.io/apimachinery/pkg/runtime"

func RegisterDefaults(scheme *runtime.Scheme) error {
	scheme.AddTypeDefaultingFunc(&RoleGraphReview{}, func(obj interface{}) {
		if review, ok := obj.(*RoleGraphReview); ok {
			SetObjectDefaults_RoleGraphReview(review)
		}
	})
	scheme.AddTypeDefaultingFunc(&SubjectPermissionsView{}, func(obj interface{}) {
		if view, ok := obj.(*SubjectPermissionsView); ok {
			SetObjectDefaults_SubjectPermissionsView(view)
		}
	})
	scheme.AddTypeDefaultingFunc(&SubjectGraphReview{}, func(obj interface{}) {
		if review, ok := obj.(*SubjectGraphReview); ok {
			SetObjectDefaults_SubjectGraphReview(review)
		}
	})
	scheme.AddTypeDefaultingFunc(&SubjectsBySelectorView{}, func(obj interface{}) {
		if view, ok := obj.(*SubjectsBySelectorView); ok {
			SetObjectDefaults_SubjectsBySelectorView(view)
		}
	})

	return nil
}

func SetObjectDefaults_RoleGraphReview(in *RoleGraphReview) {
	in.EnsureDefaults()
}

func SetObjectDefaults_SubjectPermissionsView(in *SubjectPermissionsView) {
	in.EnsureDefaults()
}

func SetObjectDefaults_SubjectGraphReview(in *SubjectGraphReview) {
	in.EnsureDefaults()
}

func SetObjectDefaults_SubjectsBySelectorView(in *SubjectsBySelectorView) {
	in.EnsureDefaults()
}
