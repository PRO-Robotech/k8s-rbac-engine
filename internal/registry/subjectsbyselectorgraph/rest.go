package subjectsbyselectorgraph

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
	authzResolver authz.ScopeResolver
}

var _ rest.Storage = &REST{}
var _ rest.Creater = &REST{}
var _ rest.SingularNameProvider = &REST{}

// NewREST returns a REST handler for subjectsbyselectorgraphs.
func NewREST(eng *engine.Engine, idx *indexer.Indexer, resolver authz.ScopeResolver) *REST {
	return &REST{engine: eng, indexer: idx, authzResolver: resolver}
}

func (r *REST) New() runtime.Object { return &rbacgraph.SubjectsBySelectorGraph{} }

func (r *REST) Destroy() {}

func (r *REST) NamespaceScoped() bool { return false }

func (r *REST) GetSingularName() string { return "subjectsbyselectorgraph" }

func (r *REST) Create(ctx context.Context, obj runtime.Object, _ rest.ValidateObjectFunc, _ *metav1.CreateOptions) (runtime.Object, error) {
	graph, ok := obj.(*rbacgraph.SubjectsBySelectorGraph)
	if !ok {
		return nil, fmt.Errorf("unexpected object type: %T", obj)
	}

	graph.Spec.EnsureDefaults()
	if err := graph.Spec.Validate(); err != nil {
		return nil, apierrors.NewBadRequest(err.Error())
	}

	if err := r.indexer.ValidateSelector(graph.Spec.Selector); err != nil {
		return nil, apierrors.NewBadRequest(err.Error())
	}

	snapshot := r.indexer.Snapshot()

	if r.authzResolver != nil {
		userInfo, hasUser := request.UserFrom(ctx)
		if !hasUser {
			return nil, errors.New("cannot enforce caller scope: no user info in request context")
		}
		scope, err := r.authzResolver.Resolve(ctx, userInfo, collectGraphScopeNamespaces(snapshot))
		if err != nil {
			return nil, fmt.Errorf("resolve caller access scope: %w", err)
		}
		snapshot = indexer.Scoped(snapshot, scope)
	}

	graph.Status = r.engine.QuerySubjectsBySelectorGraph(snapshot, graph.Spec, r.indexer.DiscoveryCache())
	graph.CreationTimestamp = metav1.Now()

	return graph, nil
}

// collectGraphScopeNamespaces returns the unique namespaces touched by
// roles and bindings in the snapshot. Used to seed the scope resolver's
// per-namespace access check.
func collectGraphScopeNamespaces(s *indexer.Snapshot) []string {
	nsSet := make(map[string]struct{})
	for _, rec := range s.RolesByID {
		if rec.Namespace != "" {
			nsSet[rec.Namespace] = struct{}{}
		}
	}
	for _, bindings := range s.BindingsByRoleRef {
		for _, b := range bindings {
			if b.Namespace != "" {
				nsSet[b.Namespace] = struct{}{}
			}
		}
	}
	out := make([]string, 0, len(nsSet))
	for ns := range nsSet {
		out = append(out, ns)
	}

	return out
}
