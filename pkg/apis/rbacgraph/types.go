package rbacgraph

import (
	"errors"
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

// ---------- SubjectPermissionsView / SubjectGraphReview types ----------
// SYNC: Keep types/constants/methods in sync with pkg/apis/rbacgraph/v1alpha1/types.go

type SubjectKind string

const (
	SubjectKindServiceAccount SubjectKind = "ServiceAccount"
	SubjectKindUser           SubjectKind = "User"
	SubjectKindGroup          SubjectKind = "Group"
)

type BindingKind string

const (
	BindingKindRoleBinding        BindingKind = "RoleBinding"
	BindingKindClusterRoleBinding BindingKind = "ClusterRoleBinding"
)

type EffectiveScope string

const (
	EffectiveScopeCluster    EffectiveScope = "cluster"
	EffectiveScopeNamespaced EffectiveScope = "namespaced"
)

type SubjectWarningCode string

const (
	SubjectWarningCodeImpersonationCapable SubjectWarningCode = "ImpersonationCapable"
	SubjectWarningCodeBrokenBinding        SubjectWarningCode = "BrokenBinding"
	SubjectWarningCodeLargeResponse        SubjectWarningCode = "LargeResponse"
)

// SubjectRef identifies an RBAC subject. Namespace is populated only for ServiceAccount.
type SubjectRef struct {
	Kind      SubjectKind
	Name      string
	Namespace string
}

// BindingRef identifies a RoleBinding or ClusterRoleBinding. Namespace is empty for ClusterRoleBinding.
type BindingRef struct {
	Kind      BindingKind
	Name      string
	Namespace string
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// SubjectPermissionsView returns the aggregated permissions of a subject
// (ServiceAccount, User, or Group) across all roles bound to it.
type SubjectPermissionsView struct {
	metav1.TypeMeta
	metav1.ObjectMeta

	Spec   SubjectPermissionsViewSpec
	Status SubjectPermissionsViewStatus
}

type SubjectPermissionsViewSpec struct {
	Subject           SubjectRef
	Selector          Selector
	MatchMode         MatchMode
	WildcardMode      WildcardMode
	DirectOnly        bool
	FilterPhantomAPIs bool
}

type SubjectPermissionsViewStatus struct {
	Subject          SubjectRef
	ResolvedSubjects []SubjectRef
	APIGroups        []APIGroupPermissions
	NonResourceURLs  *NonResourceURLPermissions
	Grants           []AttributedGrant
	Bindings         []SubjectBinding
	Roles            []SubjectRoleSummary
	Warnings         []SubjectWarning
}

type SubjectBinding struct {
	Kind           BindingKind
	Name           string
	Namespace      string
	RoleRef        RoleRef
	EffectiveScope EffectiveScope
	ViaSubject     SubjectRef
	Broken         bool
}

type SubjectRoleSummary struct {
	Ref        RoleRef
	Assessment *Assessment
	Phantom    bool
}

// AttributedGrant is one permission the subject holds, annotated with the
// role that defines it and the binding that brought the role into scope.
// Used only in SubjectPermissionsViewStatus.Grants; has no counterpart in
// role-centric responses where the source is implicit.
type AttributedGrant struct {
	SourceRole     RoleRef
	SourceBinding  BindingRef
	APIGroup       string
	Resource       string
	Verb           string
	ResourceNames  []string
	NonResourceURL string
}

type SubjectWarning struct {
	Code      SubjectWarningCode
	Message   string
	Subjects  []SubjectRef
	Binding   *BindingRef
	RoleRef   *RoleRef
	RoleCount int
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// SubjectGraphReview returns the RBAC graph (bindings, roles, rules) rooted
// at a subject. Same model as SubjectPermissionsView, projected as nodes+edges.
type SubjectGraphReview struct {
	metav1.TypeMeta
	metav1.ObjectMeta

	Spec   SubjectGraphReviewSpec
	Status SubjectGraphReviewStatus
}

type SubjectGraphReviewSpec struct {
	Subject           SubjectRef
	Selector          Selector
	MatchMode         MatchMode
	WildcardMode      WildcardMode
	DirectOnly        bool
	FilterPhantomAPIs bool
}

type SubjectGraphReviewStatus struct {
	Subject          SubjectRef
	ResolvedSubjects []SubjectRef
	MatchedRoles     int
	MatchedBindings  int
	Graph            Graph
	Warnings         []SubjectWarning
	KnownGaps        []string
}

// ---------- subject spec methods ----------

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

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// SubjectsBySelectorView returns subjects matching a selector, with role and binding provenance per grant.
type SubjectsBySelectorView struct {
	metav1.TypeMeta
	metav1.ObjectMeta

	Spec   SubjectsBySelectorViewSpec
	Status SubjectsBySelectorViewStatus
}

type SubjectsBySelectorViewSpec struct {
	Selector             Selector
	MatchMode            MatchMode
	WildcardMode         WildcardMode
	ExpandImplicitGroups bool
	FilterPhantomAPIs    bool
}

type SubjectsBySelectorViewStatus struct {
	Selector               Selector
	ExpandedImplicitGroups bool
	Subjects               []ScopedSubject
	Warnings               []SubjectWarning
}

// ScopedSubject is one subject from a selector match with attributed grants.
type ScopedSubject struct {
	Subject    SubjectRef
	Grants     []AttributedGrant
	Assessment *Assessment
}

func (s *SubjectsBySelectorViewSpec) EnsureDefaults() {
	ensureSubjectSpecDefaults(&s.MatchMode, &s.WildcardMode)
}

func (s SubjectsBySelectorViewSpec) Validate() error {
	if s.MatchMode != MatchModeAny && s.MatchMode != MatchModeAll {
		return fmt.Errorf("invalid matchMode %q", s.MatchMode)
	}
	if s.WildcardMode != WildcardModeWildcard && s.WildcardMode != WildcardModeExact {
		return fmt.Errorf("invalid wildcardMode %q", s.WildcardMode)
	}
	if !hasAnySelectorField(s.Selector) {
		return errors.New("spec.selector must specify at least one of apiGroups/resources/verbs/resourceNames/nonResourceURLs")
	}

	return nil
}

func hasAnySelectorField(s Selector) bool {
	return len(s.APIGroups) > 0 || len(s.Resources) > 0 || len(s.Verbs) > 0 ||
		len(s.ResourceNames) > 0 || len(s.NonResourceURLs) > 0
}
