package v1alpha1

import (
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	GroupName       = "rbacgraph.in-cloud.io"
	Version         = "v1alpha1"
	Kind            = "RoleGraphReview"
	Resource        = "rolegraphreviews"
	APIVersionValue = GroupName + "/" + Version
)

// +enum
type MatchMode string

const (
	MatchModeAny MatchMode = "any"
	MatchModeAll MatchMode = "all"
)

// +enum
type WildcardMode string

const (
	WildcardModeWildcard WildcardMode = "wildcard"
	WildcardModeExact    WildcardMode = "exact"
)

// +enum
type PodPhaseMode string

const (
	PodPhaseModeActive  PodPhaseMode = "active"
	PodPhaseModeAll     PodPhaseMode = "all"
	PodPhaseModeRunning PodPhaseMode = "running"

	DefaultMaxPodsPerSubject  = 20
	DefaultMaxWorkloadsPerPod = 10
)

// +enum
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

// +enum
type GraphEdgeType string

const (
	GraphEdgeTypeAggregates GraphEdgeType = "aggregates"
	GraphEdgeTypeGrants     GraphEdgeType = "grants"
	GraphEdgeTypeSubjects   GraphEdgeType = "subjects"
	GraphEdgeTypeRunsAs     GraphEdgeType = "runsAs"
	GraphEdgeTypeOwnedBy    GraphEdgeType = "ownedBy"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// RoleGraphReview queries the RBAC role graph and returns matched roles,
// bindings, subjects, and optionally pods/workloads as a directed graph.
type RoleGraphReview struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              RoleGraphReviewSpec   `json:"spec"`
	Status            RoleGraphReviewStatus `json:"status,omitempty"`
}

type RoleGraphReviewSpec struct {
	Selector            Selector       `json:"selector,omitempty"`
	MatchMode           MatchMode      `json:"matchMode,omitempty"`
	WildcardMode        WildcardMode   `json:"wildcardMode,omitempty"`
	IncludeRuleMetadata bool           `json:"includeRuleMetadata,omitempty"`
	NamespaceScope      NamespaceScope `json:"namespaceScope,omitempty"`
	IncludePods         bool           `json:"includePods,omitempty"`
	IncludeWorkloads    bool           `json:"includeWorkloads,omitempty"`
	PodPhaseMode        PodPhaseMode   `json:"podPhaseMode,omitempty"`
	MaxPodsPerSubject   int            `json:"maxPodsPerSubject,omitempty"`
	MaxWorkloadsPerPod  int            `json:"maxWorkloadsPerPod,omitempty"`
	FilterPhantomAPIs   bool           `json:"filterPhantomAPIs,omitempty"`
}

type NamespaceScope struct {
	Namespaces []string `json:"namespaces,omitempty"`
	Strict     bool     `json:"strict,omitempty"`
}

type Selector struct {
	APIGroups       []string `json:"apiGroups,omitempty"`
	Resources       []string `json:"resources,omitempty"`
	Verbs           []string `json:"verbs,omitempty"`
	ResourceNames   []string `json:"resourceNames,omitempty"`
	NonResourceURLs []string `json:"nonResourceURLs,omitempty"`
}

type RoleGraphReviewStatus struct {
	MatchedRoles     int              `json:"matchedRoles"`
	MatchedBindings  int              `json:"matchedBindings"`
	MatchedSubjects  int              `json:"matchedSubjects"`
	MatchedPods      int              `json:"matchedPods,omitempty"`
	MatchedWorkloads int              `json:"matchedWorkloads,omitempty"`
	Warnings         []string         `json:"warnings,omitempty"`
	KnownGaps        []string         `json:"knownGaps,omitempty"`
	Graph            Graph            `json:"graph"`
	ResourceMap      []ResourceMapRow `json:"resourceMap"`
}

type Graph struct {
	Nodes []GraphNode `json:"nodes"`
	Edges []GraphEdge `json:"edges"`
}

type GraphNode struct {
	ID                 string            `json:"id"`
	Type               GraphNodeType     `json:"type"`
	Name               string            `json:"name"`
	Namespace          string            `json:"namespace,omitempty"`
	Aggregated         bool              `json:"aggregated,omitempty"`
	AggregationSources []string          `json:"aggregationSources,omitempty"`
	MatchedRuleRefs    []RuleRef         `json:"matchedRuleRefs,omitempty"`
	Labels             map[string]string `json:"labels,omitempty"`
	Annotations        map[string]string `json:"annotations,omitempty"`
	PodPhase           string            `json:"podPhase,omitempty"`
	WorkloadKind       string            `json:"workloadKind,omitempty"`
	Synthetic          bool              `json:"synthetic,omitempty"`
	HiddenCount        int               `json:"hiddenCount,omitempty"`
	Assessment         *Assessment       `json:"assessment,omitempty"`
	Phantom            bool              `json:"phantom,omitempty"`
}

// Assessment summarizes policy violations for a role node.
type Assessment struct {
	HighestSeverity string   `json:"highestSeverity,omitempty"`
	CriticalCount   int      `json:"criticalCount"`
	HighCount       int      `json:"highCount"`
	MediumCount     int      `json:"mediumCount"`
	LowCount        int      `json:"lowCount"`
	TotalCount      int      `json:"totalCount"`
	CheckIDs        []string `json:"checkIDs,omitempty"`
}

type GraphEdge struct {
	ID       string        `json:"id"`
	From     string        `json:"from"`
	To       string        `json:"to"`
	Type     GraphEdgeType `json:"type"`
	RuleRefs []RuleRef     `json:"ruleRefs,omitempty"`
	Explain  string        `json:"explain,omitempty"`
}

type RuleRef struct {
	APIVersion      string    `json:"apiVersion,omitempty"`
	APIGroup        string    `json:"apiGroup,omitempty"`
	Resource        string    `json:"resource,omitempty"`
	Subresource     string    `json:"subresource,omitempty"`
	Verb            string    `json:"verb,omitempty"`
	ResourceNames   []string  `json:"resourceNames,omitempty"`
	NonResourceURLs []string  `json:"nonResourceURLs,omitempty"`
	SourceObjectUID string    `json:"sourceObjectUID,omitempty"`
	SourceRuleIndex int       `json:"sourceRuleIndex,omitempty"`
	Phantom         bool      `json:"phantom,omitempty"`
	UnsupportedVerb bool      `json:"unsupportedVerb,omitempty"`
	ExpandedRefs    []RuleRef `json:"expandedRefs,omitempty"`
}

type ResourceMapRow struct {
	APIGroup     string `json:"apiGroup,omitempty"`
	Resource     string `json:"resource,omitempty"`
	Verb         string `json:"verb,omitempty"`
	RoleCount    int    `json:"roleCount"`
	BindingCount int    `json:"bindingCount"`
	SubjectCount int    `json:"subjectCount"`
}

const (
	NonResourceURLListKind     = "NonResourceURLList"
	NonResourceURLListResource = "nonresourceurls"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// NonResourceURLList is a list of non-resource URLs found across ClusterRole rules.
type NonResourceURLList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []NonResourceURLEntry `json:"items"`
}

// NonResourceURLEntry represents a single non-resource URL with its verbs and source roles.
type NonResourceURLEntry struct {
	URL   string   `json:"url"`
	Verbs []string `json:"verbs"`
	Roles []string `json:"roles"`
}

func (NonResourceURLList) OpenAPIModelName() string {
	return openAPIPrefix + "NonResourceURLList"
}
func (NonResourceURLEntry) OpenAPIModelName() string {
	return openAPIPrefix + "NonResourceURLEntry"
}

// ---------- RolePermissionsView types ----------

// +enum
type RoleScope string

const (
	RoleScopeCluster   RoleScope = "cluster"
	RoleScopeNamespace RoleScope = "namespace"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// RolePermissionsView returns a detailed permission breakdown for a single Role or ClusterRole.
type RolePermissionsView struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   RolePermissionsViewSpec   `json:"spec"`
	Status RolePermissionsViewStatus `json:"status,omitempty"`
}

type RolePermissionsViewSpec struct {
	Role              RoleRef      `json:"role"`
	Selector          Selector     `json:"selector,omitempty"`
	MatchMode         MatchMode    `json:"matchMode,omitempty"`
	WildcardMode      WildcardMode `json:"wildcardMode,omitempty"`
	FilterPhantomAPIs bool         `json:"filterPhantomAPIs,omitempty"`
}

// +enum
type RoleRefKind string

const (
	RoleRefKindClusterRole RoleRefKind = "ClusterRole"
	RoleRefKindRole        RoleRefKind = "Role"
)

type RoleRef struct {
	Kind      RoleRefKind `json:"kind"`
	Name      string      `json:"name"`
	Namespace string      `json:"namespace,omitempty"`
}

type RolePermissionsViewStatus struct {
	Name            string                     `json:"name"`
	Scope           RoleScope                  `json:"scope"`
	APIGroups       []APIGroupPermissions      `json:"apiGroups"`
	NonResourceURLs *NonResourceURLPermissions `json:"nonResourceUrls,omitempty"`
	// Assessment is populated when the apiserver is running with report
	// enrichment enabled and an RbacReport / ClusterRbacReport exists for
	// this role. The field is omitted from JSON when nil so the response
	// shape is unchanged for callers that do not have reports installed.
	Assessment *Assessment `json:"assessment,omitempty"`
}

type APIGroupPermissions struct {
	APIGroup       string                `json:"apiGroup"`
	ResourcesCount int                   `json:"resourcesCount"`
	Resources      []ResourcePermissions `json:"resources"`
}

type ResourcePermissions struct {
	Plural  string                    `json:"plural"`
	Phantom bool                      `json:"phantom,omitempty"`
	Verbs   map[string]VerbPermission `json:"verbs"`
}

type NonResourceURLPermissions struct {
	URLsCount int                             `json:"urlsCount"`
	URLs      []NonResourceURLPermissionEntry `json:"urls"`
}

type NonResourceURLPermissionEntry struct {
	URL   string                    `json:"url"`
	Verbs map[string]VerbPermission `json:"verbs"`
}

type VerbPermission struct {
	Granted        bool           `json:"granted"`
	SupportedByAPI bool           `json:"supportedByApi"`
	Rules          []GrantingRule `json:"rules,omitempty"`
}

type GrantingRule struct {
	RuleIndex       int      `json:"ruleIndex"`
	APIGroups       []string `json:"apiGroups,omitempty"`
	Resources       []string `json:"resources,omitempty"`
	Verbs           []string `json:"verbs"`
	NonResourceURLs []string `json:"nonResourceURLs,omitempty"`
}

func (RolePermissionsView) OpenAPIModelName() string {
	return openAPIPrefix + "RolePermissionsView"
}
func (RolePermissionsViewSpec) OpenAPIModelName() string {
	return openAPIPrefix + "RolePermissionsViewSpec"
}
func (RolePermissionsViewStatus) OpenAPIModelName() string {
	return openAPIPrefix + "RolePermissionsViewStatus"
}
func (RoleRef) OpenAPIModelName() string             { return openAPIPrefix + "RoleRef" }
func (APIGroupPermissions) OpenAPIModelName() string { return openAPIPrefix + "APIGroupPermissions" }
func (ResourcePermissions) OpenAPIModelName() string { return openAPIPrefix + "ResourcePermissions" }
func (NonResourceURLPermissions) OpenAPIModelName() string {
	return openAPIPrefix + "NonResourceURLPermissions"
}
func (NonResourceURLPermissionEntry) OpenAPIModelName() string {
	return openAPIPrefix + "NonResourceURLPermissionEntry"
}
func (VerbPermission) OpenAPIModelName() string { return openAPIPrefix + "VerbPermission" }
func (GrantingRule) OpenAPIModelName() string   { return openAPIPrefix + "GrantingRule" }

func (r *RoleGraphReview) EnsureDefaults() {
	if strings.TrimSpace(r.APIVersion) == "" {
		r.APIVersion = APIVersionValue
	}
	if strings.TrimSpace(r.Kind) == "" {
		r.Kind = Kind
	}
	r.Spec.EnsureDefaults()
}

// SYNC: Keep EnsureDefaults/Validate in sync with pkg/apis/rbacgraph/types.go

func (s *RoleGraphReviewSpec) EnsureDefaults() {
	if s.MatchMode == "" {
		s.MatchMode = MatchModeAny
	}
	switch s.WildcardMode {
	case "":
		s.WildcardMode = WildcardModeWildcard
	case "expand":
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

const openAPIPrefix = "k8s-rbac-engine.pkg.apis.rbacgraph.v1alpha1."

func (RoleGraphReview) OpenAPIModelName() string     { return openAPIPrefix + "RoleGraphReview" }
func (RoleGraphReviewSpec) OpenAPIModelName() string { return openAPIPrefix + "RoleGraphReviewSpec" }
func (RoleGraphReviewStatus) OpenAPIModelName() string {
	return openAPIPrefix + "RoleGraphReviewStatus"
}
func (Selector) OpenAPIModelName() string       { return openAPIPrefix + "Selector" }
func (NamespaceScope) OpenAPIModelName() string { return openAPIPrefix + "NamespaceScope" }
func (Graph) OpenAPIModelName() string          { return openAPIPrefix + "Graph" }
func (GraphNode) OpenAPIModelName() string      { return openAPIPrefix + "GraphNode" }
func (GraphEdge) OpenAPIModelName() string      { return openAPIPrefix + "GraphEdge" }
func (Assessment) OpenAPIModelName() string     { return openAPIPrefix + "Assessment" }
func (RuleRef) OpenAPIModelName() string        { return openAPIPrefix + "RuleRef" }
func (ResourceMapRow) OpenAPIModelName() string { return openAPIPrefix + "ResourceMapRow" }
