// Package reportcache provides an in-memory, informer-backed lookup of
// RbacReport / ClusterRbacReport severity assessments. It implements
// pkg/engine.ReportLookup so the aggregated apiserver can enrich graph
// nodes and per-role views with policy-violation summaries without going
// through the kube-apiserver on every request.
package reportcache

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/rest"
	toolscache "k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/cache"

	api "k8s-rbac-engine/pkg/apis/rbacgraph"
	rrv1 "k8s-rbac-engine/pkg/apis/rbacreports/v1alpha1"
	"k8s-rbac-engine/pkg/engine"
)

var _ engine.ReportLookup = (*Cache)(nil)

var ErrCRDNotInstalled = errors.New("rbacreports.in-cloud.io/v1alpha1 CRDs not installed in cluster")

// Cache is the report cache.
type Cache struct {
	cache  cache.Cache
	mu     sync.RWMutex
	byKind map[lookupKey]*api.Assessment
}

type lookupKey struct {
	kind      string
	namespace string
	name      string
}

func New(restConfig *rest.Config, scheme *runtime.Scheme) (*Cache, error) {
	if err := probeCRDs(restConfig); err != nil {
		return nil, err
	}

	c, err := cache.New(restConfig, cache.Options{Scheme: scheme})
	if err != nil {
		return nil, fmt.Errorf("create informer cache: %w", err)
	}

	rc := &Cache{
		cache:  c,
		byKind: make(map[lookupKey]*api.Assessment),
	}

	if err := rc.installInformers(context.Background()); err != nil {
		return nil, fmt.Errorf("install informers: %w", err)
	}

	return rc, nil
}

func probeCRDs(restConfig *rest.Config) error {
	dc, err := discovery.NewDiscoveryClientForConfig(restConfig)
	if err != nil {
		return fmt.Errorf("build discovery client: %w", err)
	}

	resources, err := dc.ServerResourcesForGroupVersion(rrv1.GroupVersion.String())
	if err != nil {
		if isGroupVersionMissing(err) {
			return ErrCRDNotInstalled
		}

		return fmt.Errorf("discovery probe %s: %w", rrv1.GroupVersion, err)
	}

	want := map[string]bool{
		"rbacpolicies":       true,
		"rbacreports":        true,
		"clusterrbacreports": true,
	}
	for i := range resources.APIResources {
		delete(want, resources.APIResources[i].Name)
	}
	if len(want) > 0 {
		missing := make([]string, 0, len(want))
		for name := range want {
			missing = append(missing, name)
		}

		return fmt.Errorf("%w: missing resources %v", ErrCRDNotInstalled, missing)
	}

	return nil
}

func isGroupVersionMissing(err error) bool {
	if err == nil {
		return false
	}
	if meta.IsNoMatchError(err) {
		return true
	}

	msg := strings.ToLower(err.Error())
	if msg == "" {
		return false
	}
	for _, needle := range []string{"the server could not find the requested resource", "no matches for kind"} {
		if strings.Contains(msg, needle) {
			return true
		}
	}

	return false
}

func (c *Cache) installInformers(ctx context.Context) error {
	roleInformer, err := c.cache.GetInformer(ctx, &rrv1.RbacReport{})
	if err != nil {
		return fmt.Errorf("get RbacReport informer: %w", err)
	}
	if _, err := roleInformer.AddEventHandler(toolscache.ResourceEventHandlerFuncs{
		AddFunc:    c.onRbacReport,
		UpdateFunc: func(_, obj any) { c.onRbacReport(obj) },
		DeleteFunc: c.onRbacReportDelete,
	}); err != nil {
		return fmt.Errorf("add RbacReport handler: %w", err)
	}

	clusterInformer, err := c.cache.GetInformer(ctx, &rrv1.ClusterRbacReport{})
	if err != nil {
		return fmt.Errorf("get ClusterRbacReport informer: %w", err)
	}
	if _, err := clusterInformer.AddEventHandler(toolscache.ResourceEventHandlerFuncs{
		AddFunc:    c.onClusterRbacReport,
		UpdateFunc: func(_, obj any) { c.onClusterRbacReport(obj) },
		DeleteFunc: c.onClusterRbacReportDelete,
	}); err != nil {
		return fmt.Errorf("add ClusterRbacReport handler: %w", err)
	}

	return nil
}

func (c *Cache) Run(ctx context.Context) error {
	return c.cache.Start(ctx)
}

func (c *Cache) WaitForSync(ctx context.Context) bool {
	return c.cache.WaitForCacheSync(ctx)
}

// Lookup implements engine.ReportLookup.
func (c *Cache) Lookup(kind, namespace, name string) *api.Assessment {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.byKind[lookupKey{kind: kind, namespace: namespace, name: name}]
}

func (c *Cache) onRbacReport(obj any) {
	r, ok := obj.(*rrv1.RbacReport)
	if !ok || r == nil {
		return
	}
	roleName, namespace := resolveRoleIdentity(r.Spec.RoleRef.Name, r.Spec.RoleRef.Namespace, r.Name, r.Namespace)
	c.set(lookupKey{kind: rrv1.KindRole, namespace: namespace, name: roleName}, engine.AssessmentFromRbacReport(r))
}

func (c *Cache) onClusterRbacReport(obj any) {
	r, ok := obj.(*rrv1.ClusterRbacReport)
	if !ok || r == nil {
		return
	}
	roleName, _ := resolveRoleIdentity(r.Spec.RoleRef.Name, "", r.Name, "")
	c.set(lookupKey{kind: rrv1.KindClusterRole, namespace: "", name: roleName}, engine.AssessmentFromClusterRbacReport(r))
}

func resolveRoleIdentity(refName, refNamespace, metaName, metaNamespace string) (name, namespace string) {
	name = refName
	if name == "" {
		name = metaName
	}
	namespace = refNamespace
	if namespace == "" {
		namespace = metaNamespace
	}

	return name, namespace
}

func (c *Cache) onRbacReportDelete(obj any) {
	r, ok := unwrapDeletedFinalState[*rrv1.RbacReport](obj)
	if !ok || r == nil {
		return
	}
	roleName, namespace := resolveRoleIdentity(r.Spec.RoleRef.Name, r.Spec.RoleRef.Namespace, r.Name, r.Namespace)
	c.delete(lookupKey{kind: rrv1.KindRole, namespace: namespace, name: roleName})
}

func (c *Cache) onClusterRbacReportDelete(obj any) {
	r, ok := unwrapDeletedFinalState[*rrv1.ClusterRbacReport](obj)
	if !ok || r == nil {
		return
	}
	roleName, _ := resolveRoleIdentity(r.Spec.RoleRef.Name, "", r.Name, "")
	c.delete(lookupKey{kind: rrv1.KindClusterRole, namespace: "", name: roleName})
}

func unwrapDeletedFinalState[T any](obj any) (T, bool) {
	if v, ok := obj.(T); ok {
		return v, true
	}
	if tomb, ok := obj.(toolscache.DeletedFinalStateUnknown); ok {
		if v, ok := tomb.Obj.(T); ok {
			return v, true
		}
	}
	var zero T

	return zero, false
}

func (c *Cache) set(key lookupKey, assessment *api.Assessment) {
	if assessment == nil {
		c.delete(key)

		return
	}
	c.mu.Lock()
	c.byKind[key] = assessment
	c.mu.Unlock()
}

func (c *Cache) delete(key lookupKey) {
	c.mu.Lock()
	delete(c.byKind, key)
	c.mu.Unlock()
}

// Snapshot returns a copy of the current cache contents indexed by
// (kind, namespace, name). Used by tests; should not be called from the
// hot request path.
func (c *Cache) Snapshot() map[string]*api.Assessment {
	c.mu.RLock()
	defer c.mu.RUnlock()

	out := make(map[string]*api.Assessment, len(c.byKind))
	for k, v := range c.byKind {
		key := k.kind + "/" + k.namespace + "/" + k.name
		out[key] = v
	}

	return out
}
