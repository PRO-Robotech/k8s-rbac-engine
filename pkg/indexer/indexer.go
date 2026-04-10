package indexer

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	appslisters "k8s.io/client-go/listers/apps/v1"
	batchlisters "k8s.io/client-go/listers/batch/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	rbaclisters "k8s.io/client-go/listers/rbac/v1"

	"k8s.io/client-go/discovery"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

const rebuildDebounceInterval = 500 * time.Millisecond

type Indexer struct {
	factory informers.SharedInformerFactory

	rolesInformer               cache.SharedIndexInformer
	clusterRolesInformer        cache.SharedIndexInformer
	roleBindingsInformer        cache.SharedIndexInformer
	clusterRoleBindingsInformer cache.SharedIndexInformer
	podsInformer                cache.SharedIndexInformer
	serviceAccountsInformer     cache.SharedIndexInformer
	deploymentsInformer         cache.SharedIndexInformer
	replicaSetsInformer         cache.SharedIndexInformer
	statefulSetsInformer        cache.SharedIndexInformer
	daemonSetsInformer          cache.SharedIndexInformer
	jobsInformer                cache.SharedIndexInformer
	cronJobsInformer            cache.SharedIndexInformer

	rolesLister               rbaclisters.RoleLister
	clusterRolesLister        rbaclisters.ClusterRoleLister
	roleBindingsLister        rbaclisters.RoleBindingLister
	clusterRoleBindingsLister rbaclisters.ClusterRoleBindingLister
	podsLister                corelisters.PodLister
	serviceAccountsLister     corelisters.ServiceAccountLister
	deploymentsLister         appslisters.DeploymentLister
	replicaSetsLister         appslisters.ReplicaSetLister
	statefulSetsLister        appslisters.StatefulSetLister
	daemonSetsLister          appslisters.DaemonSetLister
	jobsLister                batchlisters.JobLister
	cronJobsLister            batchlisters.CronJobLister
	snapshot                  atomic.Pointer[Snapshot]
	synced                    atomic.Bool
	rebuildMu                 sync.Mutex
	rebuildTimer              *time.Timer
	timerMu                   sync.Mutex

	discoveryClient discovery.DiscoveryInterface
	discoveryCache  atomic.Pointer[APIDiscoveryCache]
}

// IMPORTANT — keep the kubebuilder:rbac markers below in sync with the
// informers established inside New().
//
// Every factory.X.V1().Y() call inside New() opens a list/watch against
// an apiserver resource. Every such resource MUST appear in a
// +kubebuilder:rbac marker below, otherwise the operator pod will hit
// 403 Forbidden at startup, the informer will fail to sync, and any
// feature that depends on that resource (e.g. phantom subject detection
// for ServiceAccounts) will silently degrade — informers do NOT crash
// the process on permission errors, they only log and serve stale or
// empty data.
//
// Workflow when adding a new informer:
//
//  1. Add the factory.X.V1().Y() call to New() below.
//  2. Add the corresponding resource to the relevant +kubebuilder:rbac
//     marker line below (or add a new line if it's a new API group).
//  3. Run `make manifests` — controller-gen rbac merges the markers
//     into deploy/kustomize/base/rbac/role.yaml.
//  4. Re-run `make kind-install` — the deploy will fail loudly if the
//     ClusterRole is incomplete (apiserver returns 403 in the operator
//     pod logs within seconds of the new informer starting).
//
// The markers cannot be unit-test enforced because they are comments,
// not Go code. `make kind-install` against a real cluster is the only
// gate. Adding markers and informers in the same commit is the
// discipline that prevents drift.

// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=roles;clusterroles;rolebindings;clusterrolebindings,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=pods;serviceaccounts,verbs=get;list;watch
// +kubebuilder:rbac:groups=apps,resources=deployments;replicasets;statefulsets;daemonsets,verbs=get;list;watch
// +kubebuilder:rbac:groups=batch,resources=jobs;cronjobs,verbs=get;list;watch

func New(client kubernetes.Interface, resyncPeriod time.Duration) *Indexer {
	factory := informers.NewSharedInformerFactory(client, resyncPeriod)
	roles := factory.Rbac().V1().Roles()
	clusterRoles := factory.Rbac().V1().ClusterRoles()
	roleBindings := factory.Rbac().V1().RoleBindings()
	clusterRoleBindings := factory.Rbac().V1().ClusterRoleBindings()
	pods := factory.Core().V1().Pods()
	serviceAccounts := factory.Core().V1().ServiceAccounts()
	deployments := factory.Apps().V1().Deployments()
	replicaSets := factory.Apps().V1().ReplicaSets()
	statefulSets := factory.Apps().V1().StatefulSets()
	daemonSets := factory.Apps().V1().DaemonSets()
	jobs := factory.Batch().V1().Jobs()
	cronJobs := factory.Batch().V1().CronJobs()

	i := &Indexer{
		factory:                     factory,
		discoveryClient:             client.Discovery(),
		rolesInformer:               roles.Informer(),
		clusterRolesInformer:        clusterRoles.Informer(),
		roleBindingsInformer:        roleBindings.Informer(),
		clusterRoleBindingsInformer: clusterRoleBindings.Informer(),
		podsInformer:                pods.Informer(),
		serviceAccountsInformer:     serviceAccounts.Informer(),
		deploymentsInformer:         deployments.Informer(),
		replicaSetsInformer:         replicaSets.Informer(),
		statefulSetsInformer:        statefulSets.Informer(),
		daemonSetsInformer:          daemonSets.Informer(),
		jobsInformer:                jobs.Informer(),
		cronJobsInformer:            cronJobs.Informer(),
		rolesLister:                 roles.Lister(),
		clusterRolesLister:          clusterRoles.Lister(),
		roleBindingsLister:          roleBindings.Lister(),
		clusterRoleBindingsLister:   clusterRoleBindings.Lister(),
		podsLister:                  pods.Lister(),
		serviceAccountsLister:       serviceAccounts.Lister(),
		deploymentsLister:           deployments.Lister(),
		replicaSetsLister:           replicaSets.Lister(),
		statefulSetsLister:          statefulSets.Lister(),
		daemonSetsLister:            daemonSets.Lister(),
		jobsLister:                  jobs.Lister(),
		cronJobsLister:              cronJobs.Lister(),
	}

	handler := cache.ResourceEventHandlerFuncs{
		AddFunc:    func(any) { i.scheduleRebuild() },
		UpdateFunc: func(any, any) { i.scheduleRebuild() },
		DeleteFunc: func(any) { i.scheduleRebuild() },
	}
	//nolint:errcheck,gosec // AddEventHandler only errors when the informer is stopped
	i.rolesInformer.AddEventHandler(handler)
	i.clusterRolesInformer.AddEventHandler(handler)        //nolint:errcheck,gosec // informer is running
	i.roleBindingsInformer.AddEventHandler(handler)        //nolint:errcheck,gosec // informer is running
	i.clusterRoleBindingsInformer.AddEventHandler(handler) //nolint:errcheck,gosec // informer is running
	i.podsInformer.AddEventHandler(handler)                //nolint:errcheck,gosec // informer is running
	i.serviceAccountsInformer.AddEventHandler(handler)     //nolint:errcheck,gosec // informer is running
	i.deploymentsInformer.AddEventHandler(handler)         //nolint:errcheck,gosec // informer is running
	i.replicaSetsInformer.AddEventHandler(handler)         //nolint:errcheck,gosec // informer is running
	i.statefulSetsInformer.AddEventHandler(handler)        //nolint:errcheck,gosec // informer is running
	i.daemonSetsInformer.AddEventHandler(handler)          //nolint:errcheck,gosec // informer is running
	i.jobsInformer.AddEventHandler(handler)                //nolint:errcheck,gosec // informer is running
	i.cronJobsInformer.AddEventHandler(handler)            //nolint:errcheck,gosec // informer is running

	i.snapshot.Store(newEmptySnapshot())

	return i
}

func (i *Indexer) Start(ctx context.Context) error {
	i.factory.Start(ctx.Done())

	if !cache.WaitForCacheSync(
		ctx.Done(),
		i.rolesInformer.HasSynced,
		i.clusterRolesInformer.HasSynced,
		i.roleBindingsInformer.HasSynced,
		i.clusterRoleBindingsInformer.HasSynced,
		i.podsInformer.HasSynced,
		i.serviceAccountsInformer.HasSynced,
		i.deploymentsInformer.HasSynced,
		i.replicaSetsInformer.HasSynced,
		i.statefulSetsInformer.HasSynced,
		i.daemonSetsInformer.HasSynced,
		i.jobsInformer.HasSynced,
		i.cronJobsInformer.HasSynced,
	) {
		return errors.New("failed to sync informer caches")
	}

	i.rebuild()
	i.synced.Store(true)
	go i.refreshDiscoveryLoop(ctx.Done(), 5*time.Minute)
	<-ctx.Done()

	return nil
}

func (i *Indexer) IsReady() bool {
	return i.synced.Load()
}

func (i *Indexer) DiscoveryCache() *APIDiscoveryCache {
	return i.discoveryCache.Load()
}

func (i *Indexer) Snapshot() *Snapshot {
	s := i.snapshot.Load()
	if s == nil {
		return newEmptySnapshot()
	}

	return s
}

func (i *Indexer) rebuild() {
	i.rebuildMu.Lock()
	defer i.rebuildMu.Unlock()

	next := newEmptySnapshot()
	next.BuiltAt = time.Now().UTC()

	roles := listWithWarning(i.rolesLister.List, "roles", &next.Warnings)
	clusterRoles := listWithWarning(i.clusterRolesLister.List, "clusterroles", &next.Warnings)
	roleBindings := listWithWarning(i.roleBindingsLister.List, "rolebindings", &next.Warnings)
	clusterRoleBindings := listWithWarning(i.clusterRoleBindingsLister.List, "clusterrolebindings", &next.Warnings)
	pods := listWithWarning(i.podsLister.List, "pods", &next.Warnings)
	serviceAccounts := listWithWarning(i.serviceAccountsLister.List, "serviceaccounts", &next.Warnings)
	deployments := listWithWarning(i.deploymentsLister.List, "deployments", &next.Warnings)
	replicaSets := listWithWarning(i.replicaSetsLister.List, "replicasets", &next.Warnings)
	statefulSets := listWithWarning(i.statefulSetsLister.List, "statefulsets", &next.Warnings)
	daemonSets := listWithWarning(i.daemonSetsLister.List, "daemonsets", &next.Warnings)
	jobs := listWithWarning(i.jobsLister.List, "jobs", &next.Warnings)
	cronJobs := listWithWarning(i.cronJobsLister.List, "cronjobs", &next.Warnings)

	indexRoles(next, roles)
	indexClusterRoles(next, clusterRoles)
	indexAggregatedClusterRoles(next, clusterRoles)
	indexRoleBindings(next, roleBindings)
	indexClusterRoleBindings(next, clusterRoleBindings)

	indexServiceAccounts(next, serviceAccounts)
	indexPods(next, pods)
	for _, deployment := range deployments {
		indexWorkload(next, "apps/v1", "Deployment", deployment.ObjectMeta)
	}
	for _, replicaSet := range replicaSets {
		indexWorkload(next, "apps/v1", "ReplicaSet", replicaSet.ObjectMeta)
	}
	for _, statefulSet := range statefulSets {
		indexWorkload(next, "apps/v1", "StatefulSet", statefulSet.ObjectMeta)
	}
	for _, daemonSet := range daemonSets {
		indexWorkload(next, "apps/v1", "DaemonSet", daemonSet.ObjectMeta)
	}
	for _, job := range jobs {
		indexWorkload(next, "batch/v1", "Job", job.ObjectMeta)
	}
	for _, cronJob := range cronJobs {
		indexWorkload(next, "batch/v1", "CronJob", cronJob.ObjectMeta)
	}

	sortSnapshot(next)
	i.snapshot.Store(next)
}

func (i *Indexer) scheduleRebuild() {
	i.timerMu.Lock()
	defer i.timerMu.Unlock()
	if i.rebuildTimer != nil {
		i.rebuildTimer.Stop()
	}
	i.rebuildTimer = time.AfterFunc(rebuildDebounceInterval, i.rebuild)
}
