package rbacgraph

import (
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// RoleGraphReview is the internal (hub) representation of a role graph query.
type RoleGraphReview struct {
	metav1.TypeMeta
	metav1.ObjectMeta

	Spec   RoleGraphReviewSpec
	Status RoleGraphReviewStatus
}

// ---------- typed enums ----------

type MatchMode string

const (
	MatchModeAny MatchMode = "any"
	MatchModeAll MatchMode = "all"
)

type WildcardMode string

const (
	WildcardModeWildcard WildcardMode = "wildcard"
	WildcardModeExact    WildcardMode = "exact"
)

type PodPhaseMode string

const (
	PodPhaseModeActive  PodPhaseMode = "active"
	PodPhaseModeAll     PodPhaseMode = "all"
	PodPhaseModeRunning PodPhaseMode = "running"

	DefaultMaxPodsPerSubject  = 20
	DefaultMaxWorkloadsPerPod = 10
)

type GraphNodeType string

const (
	GraphNodeTypeRole               GraphNodeType = "Role"
	GraphNodeTypeClusterRole        GraphNodeType = "ClusterRole"
	GraphNodeTypeRoleBinding        GraphNodeType = "RoleBinding"
	GraphNodeTypeClusterRoleBinding GraphNodeType = "ClusterRoleBinding"
	GraphNodeTypeUser               GraphNodeType = "User"
	GraphNodeTypeGroup              GraphNodeType = "Group"
	GraphNodeTypeServiceAccount     GraphNodeType = "ServiceAccount"
	GraphNodeTypePod                GraphNodeType = "Pod"
	GraphNodeTypeWorkload           GraphNodeType = "Workload"
	GraphNodeTypePodOverflow        GraphNodeType = "PodOverflow"
	GraphNodeTypeWorkloadOverflow   GraphNodeType = "WorkloadOverflow"
)

type GraphEdgeType string

const (
	GraphEdgeTypeAggregates GraphEdgeType = "aggregates"
	GraphEdgeTypeGrants     GraphEdgeType = "grants"
	GraphEdgeTypeSubjects   GraphEdgeType = "subjects"
	GraphEdgeTypeRunsAs     GraphEdgeType = "runsAs"
	GraphEdgeTypeOwnedBy    GraphEdgeType = "ownedBy"
)

// ---------- spec / status types ----------

type RoleGraphReviewSpec struct {
	Selector            Selector
	MatchMode           MatchMode
	WildcardMode        WildcardMode
	IncludeRuleMetadata bool
	NamespaceScope      NamespaceScope
	IncludePods         bool
	IncludeWorkloads    bool
	PodPhaseMode        PodPhaseMode
	MaxPodsPerSubject   int
	MaxWorkloadsPerPod  int
	FilterPhantomAPIs   bool
}

type NamespaceScope struct {
	Namespaces []string
	Strict     bool
}

type Selector struct {
	APIGroups       []string
	Resources       []string
	Verbs           []string
	ResourceNames   []string
	NonResourceURLs []string
}

type RoleGraphReviewStatus struct {
	MatchedRoles     int
	MatchedBindings  int
	MatchedSubjects  int
	MatchedPods      int
	MatchedWorkloads int
	Warnings         []string
	KnownGaps        []string
	Graph            Graph
	ResourceMap      []ResourceMapRow
}

type Graph struct {
	Nodes []GraphNode
	Edges []GraphEdge
}

type GraphNode struct {
	ID                 string
	Type               GraphNodeType
	Name               string
	Namespace          string
	Aggregated         bool
	AggregationSources []string
	MatchedRuleRefs    []RuleRef
	Labels             map[string]string
	Annotations        map[string]string
	PodPhase           string
	WorkloadKind       string
	Synthetic          bool
	HiddenCount        int
	Assessment         *Assessment
	Phantom            bool
}

// Assessment summarizes the policy violations attached to a role node.
type Assessment struct {
	HighestSeverity string
	CriticalCount   int
	HighCount       int
	MediumCount     int
	LowCount        int
	TotalCount      int
	CheckIDs        []string
}

type GraphEdge struct {
	ID       string
	From     string
	To       string
	Type     GraphEdgeType
	RuleRefs []RuleRef
	Explain  string
}

type RuleRef struct {
	APIVersion      string
	APIGroup        string
	Resource        string
	Subresource     string
	Verb            string
	ResourceNames   []string
	NonResourceURLs []string
	SourceObjectUID string
	SourceRuleIndex int
	Phantom         bool
	UnsupportedVerb bool
	ExpandedRefs    []RuleRef
}

type ResourceMapRow struct {
	APIGroup     string
	Resource     string
	Verb         string
	RoleCount    int
	BindingCount int
	SubjectCount int
}

// ---------- NonResourceURL types ----------

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// NonResourceURLList is a list of non-resource URLs found across ClusterRole rules.
type NonResourceURLList struct {
	metav1.TypeMeta
	metav1.ListMeta

	Items []NonResourceURLEntry
}

// NonResourceURLEntry represents a single non-resource URL with its verbs and source roles.
type NonResourceURLEntry struct {
	URL   string
	Verbs []string
	Roles []string
}

// ---------- RolePermissionsView types ----------

type RoleScope string

const (
	RoleScopeCluster   RoleScope = "cluster"
	RoleScopeNamespace RoleScope = "namespace"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// RolePermissionsView returns a detailed permission breakdown for a single Role or ClusterRole.
type RolePermissionsView struct {
	metav1.TypeMeta
	metav1.ObjectMeta

	Spec   RolePermissionsViewSpec
	Status RolePermissionsViewStatus
}

type RolePermissionsViewSpec struct {
	Role              RoleRef
	Selector          Selector
	MatchMode         MatchMode
	WildcardMode      WildcardMode
	FilterPhantomAPIs bool
}

type RoleRefKind string

const (
	RoleRefKindClusterRole RoleRefKind = "ClusterRole"
	RoleRefKindRole        RoleRefKind = "Role"
)

type RoleRef struct {
	Kind      RoleRefKind
	Name      string
	Namespace string
}

type RolePermissionsViewStatus struct {
	Name            string
	Scope           RoleScope
	APIGroups       []APIGroupPermissions
	NonResourceURLs *NonResourceURLPermissions
	// Assessment is populated when the apiserver is running with report
	// enrichment enabled and an RbacReport / ClusterRbacReport exists for
	// this role. nil means either enrichment is off (no ReportLookup
	// configured) or no report has been produced yet for this role.
	Assessment *Assessment
}

type APIGroupPermissions struct {
	APIGroup       string
	ResourcesCount int
	Resources      []ResourcePermissions
}

type ResourcePermissions struct {
	Plural  string
	Phantom bool
	Verbs   map[string]VerbPermission
}

type NonResourceURLPermissions struct {
	URLsCount int
	URLs      []NonResourceURLPermissionEntry
}

type NonResourceURLPermissionEntry struct {
	URL   string
	Verbs map[string]VerbPermission
}

type VerbPermission struct {
	Granted        bool
	SupportedByAPI bool
	Rules          []GrantingRule
}

type GrantingRule struct {
	RuleIndex       int
	APIGroups       []string
	Resources       []string
	Verbs           []string
	NonResourceURLs []string
}

// ---------- spec methods ----------
// SYNC: Keep EnsureDefaults/Validate in sync with pkg/apis/rbacgraph/v1alpha1/types.go

func (s *RoleGraphReviewSpec) EnsureDefaults() {
	if s.MatchMode == "" {
		s.MatchMode = MatchModeAny
	}
	if s.WildcardMode == "" {
		s.WildcardMode = WildcardModeWildcard
	}
	if s.PodPhaseMode == "" {
		s.PodPhaseMode = PodPhaseModeActive
	}
	if s.MaxPodsPerSubject <= 0 {
		s.MaxPodsPerSubject = DefaultMaxPodsPerSubject
	}
	if s.MaxWorkloadsPerPod <= 0 {
		s.MaxWorkloadsPerPod = DefaultMaxWorkloadsPerPod
	}
}

func (s RoleGraphReviewSpec) Validate() error {
	if s.MatchMode != MatchModeAny && s.MatchMode != MatchModeAll {
		return fmt.Errorf("invalid matchMode %q", s.MatchMode)
	}
	if s.WildcardMode != WildcardModeWildcard && s.WildcardMode != WildcardModeExact {
		return fmt.Errorf("invalid wildcardMode %q", s.WildcardMode)
	}
	podPhaseMode := s.PodPhaseMode
	if podPhaseMode == "" {
		podPhaseMode = PodPhaseModeActive
	}
	if podPhaseMode != PodPhaseModeActive && podPhaseMode != PodPhaseModeAll && podPhaseMode != PodPhaseModeRunning {
		return fmt.Errorf("invalid podPhaseMode %q", s.PodPhaseMode)
	}

	return nil
}

func (s *RoleGraphReviewSpec) NormalizeRuntimeFlags() []string {
	if s.IncludeWorkloads && !s.IncludePods {
		s.IncludePods = true

		return []string{"includeWorkloads=true requires includePods=true; includePods was enabled automatically"}
	}

	return nil
}
