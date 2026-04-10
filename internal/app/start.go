package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/endpoints/openapi"
	"k8s.io/apiserver/pkg/server"
	serveroptions "k8s.io/apiserver/pkg/server/options"
	"k8s.io/apiserver/pkg/util/compatibility"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	internalserver "k8s-rbac-engine/internal/apiserver"
	"k8s-rbac-engine/internal/authz"
	"k8s-rbac-engine/internal/controller"
	"k8s-rbac-engine/internal/reportcache"
	"k8s-rbac-engine/pkg/apis/rbacgraph/v1alpha1"
	rbacreports "k8s-rbac-engine/pkg/apis/rbacreports/v1alpha1"
	"k8s-rbac-engine/pkg/engine"
	"k8s-rbac-engine/pkg/indexer"
	"k8s-rbac-engine/pkg/kube"
)

// Mode selects which subsystems run in this process. The default "all"
// runs both the aggregated apiserver and the policy reconcilers in one
// binary; the other modes are useful for testing or for split deployments.
type Mode string

const (
	ModeAll     Mode = "all"
	ModeGraph   Mode = "graph"
	ModeReports Mode = "reports"
)

// validModes is the closed set of accepted --mode values.
var validModes = map[Mode]struct{}{
	ModeAll:     {},
	ModeGraph:   {},
	ModeReports: {},
}

// runsGraph reports whether this mode includes the aggregated API server.
func (m Mode) runsGraph() bool { return m == ModeAll || m == ModeGraph }

// runsReports reports whether this mode includes the policy reconcilers.
func (m Mode) runsReports() bool { return m == ModeAll || m == ModeReports }

type ServerOptions struct {
	RecommendedOptions     *serveroptions.RecommendedOptions
	ResyncPeriod           time.Duration
	EnforceCallerScope     bool
	Mode                   Mode
	EnableReportEnrichment bool

	StdOut io.Writer
	StdErr io.Writer
}

func NewServerOptions(out, errOut io.Writer) *ServerOptions {
	o := &ServerOptions{
		RecommendedOptions: serveroptions.NewRecommendedOptions(
			"",
			internalserver.Codecs.LegacyCodec(schema.GroupVersion{
				Group:   "rbacgraph.in-cloud.io",
				Version: "v1alpha1",
			}),
		),
		Mode:                   ModeAll,
		EnableReportEnrichment: true,
		StdOut:                 out,
		StdErr:                 errOut,
	}
	o.RecommendedOptions.Etcd = nil
	o.RecommendedOptions.Admission = nil
	o.RecommendedOptions.Features.EnablePriorityAndFairness = false

	return o
}

func NewCommandStartServer(ctx context.Context, defaults *ServerOptions) *cobra.Command {
	o := defaults
	cmd := &cobra.Command{
		Use:   "rbac-engine",
		Short: "Launch the rbac-engine: aggregated API + policy reconcilers",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := o.Complete(); err != nil {
				return err
			}
			if err := o.Validate(); err != nil {
				return err
			}

			return o.Run(ctx)
		},
	}

	flags := cmd.Flags()
	o.RecommendedOptions.AddFlags(flags)
	flags.DurationVar(&o.ResyncPeriod, "resync-period", 0, "Informer resync period (0 = no periodic resync)")
	flags.BoolVar(&o.EnforceCallerScope, "enforce-caller-scope", false,
		"Restrict query results to RBAC objects the caller has permission to list")
	flags.Var(modeFlag{&o.Mode}, "mode",
		"Subsystems to run: all (apiserver + reconcilers), graph (apiserver only), reports (reconcilers only)")
	flags.BoolVar(&o.EnableReportEnrichment, "enable-report-enrichment", true,
		"Enrich graph and per-role responses with severity from RbacReport / ClusterRbacReport CRDs. "+
			"Auto-detected via discovery: if rbacreports.in-cloud.io CRDs are not installed in the cluster, "+
			"the apiserver still starts but the Assessment field is omitted from responses. "+
			"Set to false to skip enrichment unconditionally.")

	return cmd
}

// modeFlag adapts ServerOptions.Mode to spf13/pflag's Value interface so we
// get rejection of bogus values at flag-parse time instead of at runtime.
type modeFlag struct{ target *Mode }

func (f modeFlag) String() string {
	if f.target == nil || *f.target == "" {
		return string(ModeAll)
	}

	return string(*f.target)
}

func (f modeFlag) Set(value string) error {
	m := Mode(value)
	if _, ok := validModes[m]; !ok {
		return fmt.Errorf("invalid --mode %q: must be one of all, graph, reports", value)
	}
	*f.target = m

	return nil
}

func (f modeFlag) Type() string { return "string" }

// Complete fills in fields derived from other options. Currently a no-op because
// all configuration is self-contained; kept for cobra RunE convention.
func (o *ServerOptions) Complete() error {
	return nil
}

// Validate checks ServerOptions for consistency. ResyncPeriod=0 is valid
// (disables resync) and EnforceCallerScope is a boolean, so the only field
// that needs validation is Mode.
func (o *ServerOptions) Validate() error {
	if o.Mode == "" {
		o.Mode = ModeAll
	}
	if _, ok := validModes[o.Mode]; !ok {
		return fmt.Errorf("invalid mode %q: must be one of all, graph, reports", o.Mode)
	}

	return nil
}

// Run starts the subsystems selected by Mode. In ModeAll the aggregated
// API server and the controller-runtime manager run concurrently in the
// same process, sharing one signal context via errgroup. The first
// subsystem to fail or shut down cancels the other and Run returns its
// error.
func (o *ServerOptions) Run(ctx context.Context) error {
	klog.Infof("starting rbac-engine in mode=%s", o.Mode)

	g, gctx := errgroup.WithContext(ctx)

	if o.Mode.runsGraph() {
		runGraph, err := o.buildGraphRunner()
		if err != nil {
			return err
		}
		g.Go(func() error {
			klog.Info("starting aggregated apiserver subsystem")

			return runGraph(gctx)
		})
	}

	if o.Mode.runsReports() {
		runReports, err := o.buildReportsRunner()
		if err != nil {
			return err
		}
		g.Go(func() error {
			klog.Info("starting policy reconcilers subsystem")

			return runReports(gctx)
		})
	}

	return g.Wait()
}

// buildGraphRunner constructs the aggregated API server. It is split out of
// Run so the error path is independent of buildReportsRunner: a failure to
// build the apiserver should not race with a half-started manager.
func (o *ServerOptions) buildGraphRunner() (func(context.Context) error, error) {
	serverConfig := server.NewRecommendedConfig(internalserver.Codecs)
	serverConfig.EffectiveVersion = compatibility.DefaultBuildEffectiveVersion()

	if err := o.RecommendedOptions.ApplyTo(serverConfig); err != nil {
		return nil, fmt.Errorf("apply recommended options: %w", err)
	}

	namer := openapi.NewDefinitionNamer(internalserver.Scheme)
	serverConfig.OpenAPIConfig = server.DefaultOpenAPIConfig(v1alpha1.GetOpenAPIDefinitionsWithEnums, namer)
	serverConfig.OpenAPIConfig.Info.Title = "RbacGraph"
	serverConfig.OpenAPIConfig.Info.Version = v1alpha1.Version
	serverConfig.OpenAPIV3Config = server.DefaultOpenAPIV3Config(v1alpha1.GetOpenAPIDefinitionsWithEnums, namer)
	serverConfig.OpenAPIV3Config.Info.Title = "RbacGraph"
	serverConfig.OpenAPIV3Config.Info.Version = v1alpha1.Version

	clientset, err := buildClientset(o.RecommendedOptions.CoreAPI.CoreAPIKubeconfigPath)
	if err != nil {
		return nil, fmt.Errorf("build kubernetes clientset: %w", err)
	}

	idx := indexer.New(clientset, o.ResyncPeriod)

	var resolver authz.ScopeResolver
	if o.EnforceCallerScope {
		resolver = authz.NewLocalResolver(idx.Snapshot)
	}

	reportLookup, reportRunner, err := o.buildReportLookup()
	if err != nil {
		return nil, err
	}

	eng := engine.New().WithReportLookup(reportLookup)

	config := &internalserver.Config{
		GenericConfig: serverConfig,
		Indexer:       idx,
		Engine:        eng,
		AuthzResolver: resolver,
		ReportLookup:  reportLookup,
	}

	completedConfig := config.Complete()
	rbacGraphServer, err := completedConfig.New()
	if err != nil {
		return nil, fmt.Errorf("create apiserver: %w", err)
	}

	return func(ctx context.Context) error {
		g, gctx := errgroup.WithContext(ctx)
		if reportRunner != nil {
			g.Go(func() error { return reportRunner(gctx) })
		}
		g.Go(func() error {
			return rbacGraphServer.GenericAPIServer.PrepareRun().RunWithContext(gctx)
		})

		return g.Wait()
	}, nil
}

// buildReportLookup performs the discovery probe and constructs the
// reportcache.
func (o *ServerOptions) buildReportLookup() (engine.ReportLookup, func(context.Context) error, error) {
	if !o.EnableReportEnrichment {
		klog.Info("graph enrichment DISABLED via --enable-report-enrichment=false")

		return nil, nil, nil
	}

	cfg, err := kube.ClientConfig(o.RecommendedOptions.CoreAPI.CoreAPIKubeconfigPath)
	if err != nil {
		return nil, nil, fmt.Errorf("build kubernetes config for report cache: %w", err)
	}

	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		return nil, nil, fmt.Errorf("add core scheme to report cache: %w", err)
	}
	if err := rbacreports.AddToScheme(scheme); err != nil {
		return nil, nil, fmt.Errorf("add rbacreports scheme to report cache: %w", err)
	}

	cache, err := reportcache.New(cfg, scheme)
	switch {
	case err == nil:
		klog.Info("rbacreports.in-cloud.io CRDs found; graph enrichment ENABLED")

		return cache, func(ctx context.Context) error {
			if err := cache.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
				return fmt.Errorf("report cache: %w", err)
			}

			return nil
		}, nil

	case errors.Is(err, reportcache.ErrCRDNotInstalled):
		klog.Warningf("rbacreports.in-cloud.io CRDs not installed; graph enrichment DISABLED — install dist/install.yaml or run --mode=all to create the CRDs")

		return nil, nil, nil
	default:
		return nil, nil, fmt.Errorf("init report cache: %w", err)
	}
}

// buildReportsRunner constructs a controller-runtime manager with the two
// reconcilers from internal/controller.
func (o *ServerOptions) buildReportsRunner() (func(context.Context) error, error) {
	cfg, err := kube.ClientConfig(o.RecommendedOptions.CoreAPI.CoreAPIKubeconfigPath)
	if err != nil {
		return nil, fmt.Errorf("build kubernetes config: %w", err)
	}

	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		return nil, fmt.Errorf("add core scheme: %w", err)
	}
	if err := rbacreports.AddToScheme(scheme); err != nil {
		return nil, fmt.Errorf("add rbacreports scheme: %w", err)
	}

	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:                 scheme,
		HealthProbeBindAddress: ":8081",
		Metrics:                metricsserver.Options{BindAddress: ":8080"},
	})
	if err != nil {
		return nil, fmt.Errorf("create controller-runtime manager: %w", err)
	}

	if err := mgr.AddHealthzCheck("ping", healthz.Ping); err != nil {
		return nil, fmt.Errorf("add healthz check: %w", err)
	}
	if err := mgr.AddReadyzCheck("ping", healthz.Ping); err != nil {
		return nil, fmt.Errorf("add readyz check: %w", err)
	}

	if err := (&controller.RoleReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		return nil, fmt.Errorf("setup RoleReconciler: %w", err)
	}
	if err := (&controller.ClusterRoleReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		return nil, fmt.Errorf("setup ClusterRoleReconciler: %w", err)
	}

	return mgr.Start, nil
}

func buildClientset(kubeconfig string) (kubernetes.Interface, error) {
	cfg, err := kube.ClientConfig(kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("build client config: %w", err)
	}

	return kubernetes.NewForConfig(cfg)
}
