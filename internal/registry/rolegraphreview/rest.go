package rolegraphreview

import (
	"context"
	"errors"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/registry/rest"

	"k8s-rbac-engine/internal/authz"
	"k8s-rbac-engine/pkg/apis/rbacgraph"
	"k8s-rbac-engine/pkg/engine"
	"k8s-rbac-engine/pkg/indexer"
)

type REST struct {
	engine        *engine.Engine
	indexer       *indexer.Indexer
	scheme        *runtime.Scheme
	authzResolver authz.ScopeResolver
}

var _ rest.Storage = &REST{}
var _ rest.Creater = &REST{}
var _ rest.SingularNameProvider = &REST{}

func NewREST(eng *engine.Engine, idx *indexer.Indexer, scheme *runtime.Scheme, resolver authz.ScopeResolver) *REST {
	return &REST{
		engine:        eng,
		indexer:       idx,
		scheme:        scheme,
		authzResolver: resolver,
	}
}

func (r *REST) New() runtime.Object {
	return &rbacgraph.RoleGraphReview{}
}

func (r *REST) Destroy() {}

func (r *REST) NamespaceScoped() bool {
	return false
}

func (r *REST) GetSingularName() string {
	return "rolegraphreview"
}

func (r *REST) Create(ctx context.Context, obj runtime.Object, _ rest.ValidateObjectFunc, _ *metav1.CreateOptions) (runtime.Object, error) {
	review, ok := obj.(*rbacgraph.RoleGraphReview)
	if !ok {
		return nil, fmt.Errorf("unexpected object type: %T", obj)
	}

	review.Spec.EnsureDefaults()
	if err := review.Spec.Validate(); err != nil {
		return nil, err
	}

	if err := r.indexer.ValidateSelector(review.Spec.Selector); err != nil {
		return nil, apierrors.NewBadRequest(err.Error())
	}

	snapshot := r.indexer.Snapshot()

	var scopeWarnings []string
	if r.authzResolver != nil {
		userInfo, ok := request.UserFrom(ctx)
		if !ok {
			return nil, errors.New("cannot enforce caller scope: no user info in request context")
		}
		namespacesToCheck := collectNamespacesFromSnapshot(snapshot, review.Spec.NamespaceScope)
		scope, err := r.authzResolver.Resolve(ctx, userInfo, namespacesToCheck)
		if err != nil {
			return nil, fmt.Errorf("resolve caller access scope: %w", err)
		}
		snapshot = indexer.Scoped(snapshot, scope)
		scopeWarnings = scope.Warnings
	}

	review.Status = r.engine.Query(snapshot, review.Spec, r.indexer.DiscoveryCache())

	if len(scopeWarnings) > 0 {
		review.Status.Warnings = append(review.Status.Warnings, scopeWarnings...)
	}

	review.CreationTimestamp = metav1.Now()

	return review, nil
}

// collectNamespacesFromSnapshot extracts unique namespaces from the snapshot,
// optionally filtered by the NamespaceScope from the request spec.
func collectNamespacesFromSnapshot(s *indexer.Snapshot, nsScope rbacgraph.NamespaceScope) []string {
	nsSet := make(map[string]struct{})
	addNS := func(ns string) {
		if ns != "" {
			nsSet[ns] = struct{}{}
		}
	}
	for _, rec := range s.RolesByID {
		addNS(rec.Namespace)
	}
	for _, bindings := range s.BindingsByRoleRef {
		for _, b := range bindings {
			addNS(b.Namespace)
		}
	}
	for key := range s.PodsByServiceAccount {
		addNS(key.Namespace)
	}
	for _, w := range s.WorkloadsByUID {
		addNS(w.Namespace)
	}

	// If the caller specified explicit namespaces, intersect.
	if len(nsScope.Namespaces) > 0 {
		allowed := make(map[string]struct{}, len(nsScope.Namespaces))
		for _, ns := range nsScope.Namespaces {
			allowed[ns] = struct{}{}
		}
		for ns := range nsSet {
			if _, ok := allowed[ns]; !ok {
				delete(nsSet, ns)
			}
		}
	}

	out := make([]string, 0, len(nsSet))
	for ns := range nsSet {
		out = append(out, ns)
	}

	return out
}
