package apiserver

import (
	"errors"
	"fmt"
	"net/http"

	"k8s.io/apiserver/pkg/registry/rest"
	genericapiserver "k8s.io/apiserver/pkg/server"
	"k8s.io/apiserver/pkg/server/healthz"
	"k8s.io/klog/v2"

	"k8s-rbac-engine/internal/authz"
	nonresourceurlstorage "k8s-rbac-engine/internal/registry/nonresourceurl"
	reviewstorage "k8s-rbac-engine/internal/registry/rolegraphreview"
	permviewstorage "k8s-rbac-engine/internal/registry/rolepermissionsview"
	"k8s-rbac-engine/pkg/apis/rbacgraph"
	"k8s-rbac-engine/pkg/apis/rbacgraph/v1alpha1"
	"k8s-rbac-engine/pkg/engine"
	"k8s-rbac-engine/pkg/indexer"
)

type Config struct {
	GenericConfig *genericapiserver.RecommendedConfig
	Indexer       *indexer.Indexer
	Engine        *engine.Engine
	AuthzResolver authz.ScopeResolver
	ReportLookup  engine.ReportLookup
}

type completedConfig struct {
	GenericConfig genericapiserver.CompletedConfig
	Indexer       *indexer.Indexer
	Engine        *engine.Engine
	AuthzResolver authz.ScopeResolver
	ReportLookup  engine.ReportLookup
}

type CompletedConfig struct {
	*completedConfig
}

func (cfg *Config) Complete() CompletedConfig {
	c := completedConfig{
		GenericConfig: cfg.GenericConfig.Complete(),
		Indexer:       cfg.Indexer,
		Engine:        cfg.Engine,
		AuthzResolver: cfg.AuthzResolver,
		ReportLookup:  cfg.ReportLookup,
	}

	return CompletedConfig{&c}
}

type RbacGraphServer struct {
	GenericAPIServer *genericapiserver.GenericAPIServer
	Indexer          *indexer.Indexer
}

func (c CompletedConfig) New() (*RbacGraphServer, error) {
	genericServer, err := c.GenericConfig.New("rbacgraph-apiserver", genericapiserver.NewEmptyDelegate())
	if err != nil {
		return nil, err
	}

	s := &RbacGraphServer{
		GenericAPIServer: genericServer,
		Indexer:          c.Indexer,
	}

	apiGroupInfo := genericapiserver.NewDefaultAPIGroupInfo(rbacgraph.GroupName, Scheme, ParameterCodec, Codecs)
	v1alpha1storage := map[string]rest.Storage{}
	v1alpha1storage["rolegraphreviews"] = reviewstorage.NewREST(c.Engine, c.Indexer, Scheme, c.AuthzResolver)
	v1alpha1storage["nonresourceurls"] = nonresourceurlstorage.NewREST(c.Indexer)
	v1alpha1storage["rolepermissionsviews"] = permviewstorage.NewREST(c.Indexer, c.ReportLookup)
	apiGroupInfo.VersionedResourcesStorageMap[v1alpha1.Version] = v1alpha1storage

	if err := s.GenericAPIServer.InstallAPIGroup(&apiGroupInfo); err != nil {
		return nil, fmt.Errorf("install API group: %w", err)
	}

	s.GenericAPIServer.AddPostStartHookOrDie("start-rbacgraph-indexer", func(hookCtx genericapiserver.PostStartHookContext) error {
		go func() {
			if err := c.Indexer.Start(hookCtx); err != nil {
				klog.Errorf("indexer failed: %v", err)
			}
		}()

		return nil
	})

	if err := s.GenericAPIServer.AddReadyzChecks(indexerHealthChecker{indexer: c.Indexer}); err != nil {
		return nil, fmt.Errorf("add readyz check: %w", err)
	}

	return s, nil
}

type indexerHealthChecker struct {
	indexer *indexer.Indexer
}

func (c indexerHealthChecker) Name() string {
	return "rbacgraph-indexer"
}

func (c indexerHealthChecker) Check(_ *http.Request) error {
	if !c.indexer.IsReady() {
		return errors.New("indexer not ready")
	}

	return nil
}

var _ healthz.HealthChecker = indexerHealthChecker{}
