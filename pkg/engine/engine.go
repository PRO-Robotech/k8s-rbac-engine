package engine

import (
	api "k8s-rbac-engine/pkg/apis/rbacgraph"
	"k8s-rbac-engine/pkg/indexer"
	"k8s-rbac-engine/pkg/matcher"
)

// Engine builds RoleGraphReview responses from a snapshot.
type Engine struct {
	ReportLookup ReportLookup
}

// New returns an Engine with no ReportLookup configured.
func New() *Engine {
	return &Engine{}
}

// WithReportLookup sets the ReportLookup and returns the engine for chaining.
func (e *Engine) WithReportLookup(lookup ReportLookup) *Engine {
	e.ReportLookup = lookup

	return e
}

type queryContext struct {
	snapshot        *indexer.Snapshot
	spec            api.RoleGraphReviewSpec
	discovery       *indexer.APIDiscoveryCache
	reportLookup    ReportLookup
	status          api.RoleGraphReviewStatus
	nodeSeen        map[string]struct{}
	nodeIndex       map[string]int
	edgeSeen        map[string]struct{}
	roleSeen        map[indexer.RoleID]struct{}
	bindingSeen     map[string]struct{}
	subjectSeen     map[string]struct{}
	resourceRows    map[resourceRowKey]*resourceAccumulator
	namespaceFilter map[string]struct{}
	namespaceStrict bool
	saSubjects      map[string]subjectServiceAccount
	warningSeen     map[string]struct{}
	knownGapSeen    map[string]struct{}
	podSeen         map[string]struct{}
	workloadSeen    map[string]struct{}
}

func newQueryContext(snapshot *indexer.Snapshot, spec api.RoleGraphReviewSpec) *queryContext {
	normalizedSpec := spec
	normalizedSpec.EnsureDefaults()

	status := api.RoleGraphReviewStatus{
		Graph: api.Graph{
			Nodes: []api.GraphNode{},
			Edges: []api.GraphEdge{},
		},
		ResourceMap: []api.ResourceMapRow{},
		Warnings:    snapshot.CloneWarnings(),
		KnownGaps:   snapshot.CloneKnownGaps(),
	}

	warningSeen := make(map[string]struct{}, len(status.Warnings))
	for _, warning := range status.Warnings {
		warningSeen[warning] = struct{}{}
	}
	for _, warning := range normalizedSpec.NormalizeRuntimeFlags() {
		appendUniqueString(&status.Warnings, warningSeen, warning)
	}

	knownGapSeen := make(map[string]struct{}, len(status.KnownGaps))
	for _, knownGap := range status.KnownGaps {
		knownGapSeen[knownGap] = struct{}{}
	}
	if normalizedSpec.IncludePods {
		appendUniqueString(
			&status.KnownGaps,
			knownGapSeen,
			"runtime chain is currently limited to serviceAccount subjects; user/group subject to workload mapping is not included",
		)
	}

	return &queryContext{
		snapshot:        snapshot,
		spec:            normalizedSpec,
		status:          status,
		nodeSeen:        make(map[string]struct{}),
		nodeIndex:       make(map[string]int),
		edgeSeen:        make(map[string]struct{}),
		roleSeen:        make(map[indexer.RoleID]struct{}),
		bindingSeen:     make(map[string]struct{}),
		subjectSeen:     make(map[string]struct{}),
		resourceRows:    make(map[resourceRowKey]*resourceAccumulator),
		namespaceFilter: makeNamespaceFilter(normalizedSpec.NamespaceScope.Namespaces),
		namespaceStrict: normalizedSpec.NamespaceScope.Strict,
		saSubjects:      make(map[string]subjectServiceAccount),
		warningSeen:     warningSeen,
		knownGapSeen:    knownGapSeen,
		podSeen:         make(map[string]struct{}),
		workloadSeen:    make(map[string]struct{}),
	}
}

func (qc *queryContext) finalize() api.RoleGraphReviewStatus {
	qc.status.MatchedRoles = len(qc.roleSeen)
	qc.status.MatchedBindings = len(qc.bindingSeen)
	qc.status.MatchedSubjects = len(qc.subjectSeen)
	qc.status.MatchedPods = len(qc.podSeen)
	qc.status.MatchedWorkloads = len(qc.workloadSeen)
	qc.status.ResourceMap = collapseResourceRows(qc.resourceRows)
	sortNodes(qc.status.Graph.Nodes)
	sortEdges(qc.status.Graph.Edges)

	return qc.status
}

func (e *Engine) Query(snapshot *indexer.Snapshot, spec api.RoleGraphReviewSpec, discovery *indexer.APIDiscoveryCache) api.RoleGraphReviewStatus {
	qc := newQueryContext(snapshot, spec)
	qc.discovery = discovery
	qc.reportLookup = e.ReportLookup

	roleIDs := snapshot.CandidateRoleIDs(qc.spec.Selector, qc.spec.WildcardMode)
	if len(roleIDs) == 0 {
		return qc.status
	}

	qc.buildRBACGraph(roleIDs)
	qc.expandRuntimeChain()

	return qc.finalize()
}

func matchRole(role *indexer.RoleRecord, spec api.RoleGraphReviewSpec) []api.RuleRef {
	refs := make([]api.RuleRef, 0)
	for idx, rule := range role.Rules {
		result := matcher.MatchRule(matcher.MatchInput{
			Rule:         rule,
			Selector:     spec.Selector,
			Mode:         spec.MatchMode,
			WildcardMode: spec.WildcardMode,
			SourceUID:    string(role.UID),
			RuleIndex:    idx,
		})
		if !result.Matched {
			continue
		}
		refs = append(refs, result.RuleRefs...)
	}
	if !spec.IncludeRuleMetadata {
		for i := range refs {
			refs[i].SourceObjectUID = ""
			refs[i].SourceRuleIndex = 0
		}
	}

	return refs
}
