package v1alpha1

import (
	"errors"
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

// ---------- SubjectPermissionsView / SubjectGraphReview types ----------
// SYNC: Keep types/constants/methods in sync with pkg/apis/rbacgraph/types.go

const (
	SubjectPermissionsViewKind     = "SubjectPermissionsView"
	SubjectPermissionsViewResource = "subjectpermissionsviews"
	SubjectGraphReviewKind         = "SubjectGraphReview"
	SubjectGraphReviewResource     = "subjectgraphreviews"
)

// +enum
type SubjectKind string

const (
	SubjectKindServiceAccount SubjectKind = "ServiceAccount"
	SubjectKindUser           SubjectKind = "User"
	SubjectKindGroup          SubjectKind = "Group"
)

// +enum
type BindingKind string

const (
	BindingKindRoleBinding        BindingKind = "RoleBinding"
	BindingKindClusterRoleBinding BindingKind = "ClusterRoleBinding"
)

// +enum
type EffectiveScope string

const (
	EffectiveScopeCluster    EffectiveScope = "cluster"
	EffectiveScopeNamespaced EffectiveScope = "namespaced"
)

// +enum
type SubjectWarningCode string

const (
	SubjectWarningCodeImpersonationCapable SubjectWarningCode = "ImpersonationCapable"
	SubjectWarningCodeBrokenBinding        SubjectWarningCode = "BrokenBinding"
	SubjectWarningCodeLargeResponse        SubjectWarningCode = "LargeResponse"
)

// SubjectRef identifies an RBAC subject. Namespace is populated only for ServiceAccount.
type SubjectRef struct {
	Kind      SubjectKind `json:"kind"`
	Name      string      `json:"name"`
	Namespace string      `json:"namespace,omitempty"`
}

// BindingRef identifies a RoleBinding or ClusterRoleBinding. Namespace is empty for ClusterRoleBinding.
type BindingRef struct {
	Kind      BindingKind `json:"kind"`
	Name      string      `json:"name"`
	Namespace string      `json:"namespace,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// SubjectPermissionsView returns the aggregated permissions of a subject
// (ServiceAccount, User, or Group) across all roles bound to it.
type SubjectPermissionsView struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   SubjectPermissionsViewSpec   `json:"spec"`
	Status SubjectPermissionsViewStatus `json:"status,omitempty"`
}

type SubjectPermissionsViewSpec struct {
	Subject           SubjectRef   `json:"subject"`
	Selector          Selector     `json:"selector,omitempty"`
	MatchMode         MatchMode    `json:"matchMode,omitempty"`
	WildcardMode      WildcardMode `json:"wildcardMode,omitempty"`
	DirectOnly        bool         `json:"directOnly,omitempty"`
	FilterPhantomAPIs bool         `json:"filterPhantomAPIs,omitempty"`
}

type SubjectPermissionsViewStatus struct {
	Subject          SubjectRef                 `json:"subject"`
	ResolvedSubjects []SubjectRef               `json:"resolvedSubjects,omitempty"`
	APIGroups        []APIGroupPermissions      `json:"apiGroups"`
	NonResourceURLs  *NonResourceURLPermissions `json:"nonResourceUrls,omitempty"`
	Grants           []AttributedGrant          `json:"grants"`
	Bindings         []SubjectBinding           `json:"bindings"`
	Roles            []SubjectRoleSummary       `json:"roles"`
	Warnings         []SubjectWarning           `json:"warnings,omitempty"`
}

type SubjectBinding struct {
	Kind           BindingKind    `json:"kind"`
	Name           string         `json:"name"`
	Namespace      string         `json:"namespace,omitempty"`
	RoleRef        RoleRef        `json:"roleRef"`
	EffectiveScope EffectiveScope `json:"effectiveScope"`
	ViaSubject     SubjectRef     `json:"viaSubject"`
	Broken         bool           `json:"broken,omitempty"`
}

type SubjectRoleSummary struct {
	Ref        RoleRef     `json:"ref"`
	Assessment *Assessment `json:"assessment,omitempty"`
	Phantom    bool        `json:"phantom,omitempty"`
}

// AttributedGrant is one permission the subject holds, annotated with the
// role that defines it and the binding that brought the role into scope.
// Used only in SubjectPermissionsViewStatus.Grants; has no counterpart in
// role-centric responses where the source is implicit.
type AttributedGrant struct {
	SourceRole     RoleRef    `json:"sourceRole"`
	SourceBinding  BindingRef `json:"sourceBinding"`
	APIGroup       string     `json:"apiGroup,omitempty"`
	Resource       string     `json:"resource,omitempty"`
	Verb           string     `json:"verb"`
	ResourceNames  []string   `json:"resourceNames,omitempty"`
	NonResourceURL string     `json:"nonResourceURL,omitempty"`
}

type SubjectWarning struct {
	Code      SubjectWarningCode `json:"code"`
	Message   string             `json:"message"`
	Subjects  []SubjectRef       `json:"subjects,omitempty"`
	Binding   *BindingRef        `json:"binding,omitempty"`
	RoleRef   *RoleRef           `json:"roleRef,omitempty"`
	RoleCount int                `json:"roleCount,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// SubjectGraphReview returns the RBAC graph (bindings, roles, rules) rooted
// at a subject. Same model as SubjectPermissionsView, projected as nodes+edges.
type SubjectGraphReview struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   SubjectGraphReviewSpec   `json:"spec"`
	Status SubjectGraphReviewStatus `json:"status,omitempty"`
}

type SubjectGraphReviewSpec struct {
	Subject           SubjectRef   `json:"subject"`
	Selector          Selector     `json:"selector,omitempty"`
	MatchMode         MatchMode    `json:"matchMode,omitempty"`
	WildcardMode      WildcardMode `json:"wildcardMode,omitempty"`
	DirectOnly        bool         `json:"directOnly,omitempty"`
	FilterPhantomAPIs bool         `json:"filterPhantomAPIs,omitempty"`
}

type SubjectGraphReviewStatus struct {
	Subject          SubjectRef       `json:"subject"`
	ResolvedSubjects []SubjectRef     `json:"resolvedSubjects,omitempty"`
	MatchedRoles     int              `json:"matchedRoles"`
	MatchedBindings  int              `json:"matchedBindings"`
	Graph            Graph            `json:"graph"`
	Warnings         []SubjectWarning `json:"warnings,omitempty"`
	KnownGaps        []string         `json:"knownGaps,omitempty"`
}

// ---------- subject spec methods ----------

func (r *SubjectPermissionsView) EnsureDefaults() {
	if strings.TrimSpace(r.APIVersion) == "" {
		r.APIVersion = APIVersionValue
	}
	if strings.TrimSpace(r.Kind) == "" {
		r.Kind = SubjectPermissionsViewKind
	}
	r.Spec.EnsureDefaults()
}

func (r *SubjectGraphReview) EnsureDefaults() {
	if strings.TrimSpace(r.APIVersion) == "" {
		r.APIVersion = APIVersionValue
	}
	if strings.TrimSpace(r.Kind) == "" {
		r.Kind = SubjectGraphReviewKind
	}
	r.Spec.EnsureDefaults()
}

func (s *SubjectPermissionsViewSpec) EnsureDefaults() {
	ensureSubjectSpecDefaults(&s.MatchMode, &s.WildcardMode)
}

func (s SubjectPermissionsViewSpec) Validate() error {
	return validateSubjectSpec(s.Subject, s.MatchMode, s.WildcardMode)
}

func (s *SubjectGraphReviewSpec) EnsureDefaults() {
	ensureSubjectSpecDefaults(&s.MatchMode, &s.WildcardMode)
}

func (s SubjectGraphReviewSpec) Validate() error {
	return validateSubjectSpec(s.Subject, s.MatchMode, s.WildcardMode)
}

func ensureSubjectSpecDefaults(matchMode *MatchMode, wildcardMode *WildcardMode) {
	if *matchMode == "" {
		*matchMode = MatchModeAny
	}
	switch *wildcardMode {
	case "":
		*wildcardMode = WildcardModeWildcard
	case "expand":
		*wildcardMode = WildcardModeWildcard
	}
}

func validateSubjectSpec(subject SubjectRef, matchMode MatchMode, wildcardMode WildcardMode) error {
	if subject.Kind == "" {
		return errors.New("subject.kind is required")
	}
	switch subject.Kind {
	case SubjectKindServiceAccount, SubjectKindUser, SubjectKindGroup:
	default:
		return fmt.Errorf("invalid subject.kind %q", subject.Kind)
	}
	if subject.Name == "" {
		return errors.New("subject.name is required")
	}
	if subject.Kind == SubjectKindServiceAccount && subject.Namespace == "" {
		return errors.New("subject.namespace is required for ServiceAccount")
	}
	if subject.Kind != SubjectKindServiceAccount && subject.Namespace != "" {
		return fmt.Errorf("subject.namespace must be empty for kind %q", subject.Kind)
	}
	if matchMode != MatchModeAny && matchMode != MatchModeAll {
		return fmt.Errorf("invalid matchMode %q", matchMode)
	}
	if wildcardMode != WildcardModeWildcard && wildcardMode != WildcardModeExact {
		return fmt.Errorf("invalid wildcardMode %q", wildcardMode)
	}

	return nil
}

func (SubjectPermissionsView) OpenAPIModelName() string {
	return openAPIPrefix + "SubjectPermissionsView"
}
func (SubjectPermissionsViewSpec) OpenAPIModelName() string {
	return openAPIPrefix + "SubjectPermissionsViewSpec"
}
func (SubjectPermissionsViewStatus) OpenAPIModelName() string {
	return openAPIPrefix + "SubjectPermissionsViewStatus"
}
func (SubjectGraphReview) OpenAPIModelName() string {
	return openAPIPrefix + "SubjectGraphReview"
}
func (SubjectGraphReviewSpec) OpenAPIModelName() string {
	return openAPIPrefix + "SubjectGraphReviewSpec"
}
func (SubjectGraphReviewStatus) OpenAPIModelName() string {
	return openAPIPrefix + "SubjectGraphReviewStatus"
}
func (SubjectRef) OpenAPIModelName() string         { return openAPIPrefix + "SubjectRef" }
func (BindingRef) OpenAPIModelName() string         { return openAPIPrefix + "BindingRef" }
func (SubjectBinding) OpenAPIModelName() string     { return openAPIPrefix + "SubjectBinding" }
func (SubjectRoleSummary) OpenAPIModelName() string { return openAPIPrefix + "SubjectRoleSummary" }
func (SubjectWarning) OpenAPIModelName() string     { return openAPIPrefix + "SubjectWarning" }
func (AttributedGrant) OpenAPIModelName() string    { return openAPIPrefix + "AttributedGrant" }
