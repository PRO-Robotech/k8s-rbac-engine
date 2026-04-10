package v1alpha1

import "k8s.io/apimachinery/pkg/runtime"

func RegisterDefaults(scheme *runtime.Scheme) error {
	scheme.AddTypeDefaultingFunc(&RoleGraphReview{}, func(obj interface{}) {
		if review, ok := obj.(*RoleGraphReview); ok {
			SetObjectDefaults_RoleGraphReview(review)
		}
	})

	return nil
}

func SetObjectDefaults_RoleGraphReview(in *RoleGraphReview) {
	in.EnsureDefaults()
}
