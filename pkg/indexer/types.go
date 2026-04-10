package indexer

import (
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

type RoleRefKey struct {
	Kind      string
	Namespace string
	Name      string
}

func (k RoleRefKey) String() string {
	return fmt.Sprintf("%s:%s/%s", k.Kind, k.Namespace, k.Name)
}

type RoleID string

type ServiceAccountKey struct {
	Namespace string
	Name      string
}

func (k ServiceAccountKey) String() string {
	return k.Namespace + "/" + k.Name
}

const (
	KindRole               = "Role"
	KindClusterRole        = "ClusterRole"
	KindRoleBinding        = "RoleBinding"
	KindClusterRoleBinding = "ClusterRoleBinding"

	SubjectKindServiceAccount = "ServiceAccount"
	SubjectKindGroup          = "Group"
	SubjectKindUser           = "User"

	DefaultServiceAccountName = "default"
)

type RoleRecord struct {
	UID         types.UID
	Kind        string
	Namespace   string
	Name        string
	Labels      map[string]string
	Annotations map[string]string
	Rules       []rbacv1.PolicyRule
	RuleCount   int
}

type BindingRecord struct {
	UID       types.UID
	Kind      string
	Namespace string
	Name      string
	RoleRef   RoleRefKey
	Subjects  []rbacv1.Subject
}

type PodRecord struct {
	UID                types.UID
	Namespace          string
	Name               string
	ServiceAccountName string
	Phase              corev1.PodPhase
	OwnerReferences    []metav1.OwnerReference
}

type WorkloadRecord struct {
	UID             types.UID
	APIVersion      string
	Kind            string
	Namespace       string
	Name            string
	OwnerReferences []metav1.OwnerReference
}

// Scope abstracts the access-scope check used by Scoped().
// authz.AccessScope satisfies this interface.
type Scope interface {
	IsUnrestricted() bool
	AllowRole(namespace string) bool
	AllowBinding(namespace string) bool
	AllowPod(namespace string) bool
	AllowWorkload(namespace string) bool
}

type Snapshot struct {
	BuiltAt               time.Time
	RolesByID             map[RoleID]*RoleRecord
	BindingsByRoleRef     map[RoleRefKey][]*BindingRecord
	AggregatedRoleSources map[RoleID][]RoleID
	PodsByServiceAccount  map[ServiceAccountKey][]*PodRecord
	ServiceAccounts       map[ServiceAccountKey]struct{}
	WorkloadsByUID        map[types.UID]*WorkloadRecord
	RoleIDsByVerb         map[string]map[RoleID]struct{}
	RoleIDsByResource     map[string]map[RoleID]struct{}
	RoleIDsByAPIGroup     map[string]map[RoleID]struct{}
	AllRoleIDs            []RoleID
	KnownGaps             []string
	Warnings              []string
}

func (s *Snapshot) CloneKnownGaps() []string {
	if len(s.KnownGaps) == 0 {
		return nil
	}
	out := make([]string, len(s.KnownGaps))
	copy(out, s.KnownGaps)

	return out
}

func (s *Snapshot) CloneWarnings() []string {
	if len(s.Warnings) == 0 {
		return nil
	}
	out := make([]string, len(s.Warnings))
	copy(out, s.Warnings)

	return out
}
