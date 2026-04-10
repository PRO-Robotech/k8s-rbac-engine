package indexer

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
)

func newEmptySnapshot() *Snapshot {
	return &Snapshot{
		BuiltAt:               time.Now().UTC(),
		RolesByID:             make(map[RoleID]*RoleRecord),
		BindingsByRoleRef:     make(map[RoleRefKey][]*BindingRecord),
		AggregatedRoleSources: make(map[RoleID][]RoleID),
		PodsByServiceAccount:  make(map[ServiceAccountKey][]*PodRecord),
		ServiceAccounts:       make(map[ServiceAccountKey]struct{}),
		WorkloadsByUID:        make(map[types.UID]*WorkloadRecord),
		RoleIDsByVerb:         make(map[string]map[RoleID]struct{}),
		RoleIDsByResource:     make(map[string]map[RoleID]struct{}),
		RoleIDsByAPIGroup:     make(map[string]map[RoleID]struct{}),
		AllRoleIDs:            []RoleID{},
	}
}

func listWithWarning[T any](
	listFn func(labels.Selector) ([]*T, error),
	resourceName string,
	warnings *[]string,
) []*T {
	items, err := listFn(labels.Everything())
	if err != nil {
		*warnings = append(*warnings, fmt.Sprintf("%s list failed: %v", resourceName, err))
	}

	return items
}

func indexRoleTokens(s *Snapshot, roleID RoleID, rules []rbacv1.PolicyRule) {
	for _, rule := range rules {
		for _, group := range normalizedSlice(rule.APIGroups) {
			insertIndex(s.RoleIDsByAPIGroup, group, roleID)
		}
		for _, resource := range normalizedSlice(rule.Resources) {
			if resource == "" {
				continue
			}
			insertIndex(s.RoleIDsByResource, resource, roleID)
		}
		for _, verb := range normalizedSlice(rule.Verbs) {
			if verb == "" {
				continue
			}
			insertIndex(s.RoleIDsByVerb, verb, roleID)
		}
	}
}

func indexWorkload(snapshot *Snapshot, apiVersion, kind string, meta metav1.ObjectMeta) {
	if meta.UID == "" {
		return
	}
	snapshot.WorkloadsByUID[meta.UID] = &WorkloadRecord{
		UID:             meta.UID,
		APIVersion:      apiVersion,
		Kind:            kind,
		Namespace:       meta.Namespace,
		Name:            meta.Name,
		OwnerReferences: cloneSlice(meta.OwnerReferences),
	}
}

func indexRoleRecord(next *Snapshot, uid types.UID, kind, namespace, name string,
	lbls, annotations map[string]string, rules []rbacv1.PolicyRule,
) {
	rec := &RoleRecord{
		UID:         uid,
		Kind:        kind,
		Namespace:   namespace,
		Name:        name,
		Labels:      cloneMap(lbls),
		Annotations: cloneMap(annotations),
		Rules:       cloneSlice(rules),
		RuleCount:   len(rules),
	}
	id := RecID(kind, namespace, name)
	next.RolesByID[id] = rec
	next.AllRoleIDs = append(next.AllRoleIDs, id)
	indexRoleTokens(next, id, rec.Rules)
}

func indexRoles(next *Snapshot, roles []*rbacv1.Role) {
	for _, role := range roles {
		indexRoleRecord(next, role.UID, KindRole, role.Namespace, role.Name,
			role.Labels, role.Annotations, role.Rules)
	}
}

func indexClusterRoles(next *Snapshot, clusterRoles []*rbacv1.ClusterRole) {
	for _, role := range clusterRoles {
		indexRoleRecord(next, role.UID, KindClusterRole, "", role.Name,
			role.Labels, role.Annotations, role.Rules)
		if role.AggregationRule != nil && len(role.Rules) == 0 {
			next.KnownGaps = append(next.KnownGaps, fmt.Sprintf("clusterrole/%s has aggregationRule but resolved rules are empty", role.Name))
		}
	}
}

// labelEntry is a (key, value) pair used as a map key for the label index.
type labelEntry struct{ key, value string }

//nolint:gocognit,gocyclo // multi-selector aggregation with label matching; reduced from original but inherently complex
func indexAggregatedClusterRoles(snapshot *Snapshot, clusterRoles []*rbacv1.ClusterRole) {
	if len(clusterRoles) == 0 {
		return
	}

	// Pre-build label index: (key, value) → list of ClusterRoles.
	labelIndex := make(map[labelEntry][]*rbacv1.ClusterRole)
	for _, cr := range clusterRoles {
		for k, v := range cr.Labels {
			entry := labelEntry{k, v}
			labelIndex[entry] = append(labelIndex[entry], cr)
		}
	}

	for _, target := range clusterRoles {
		if target.AggregationRule == nil || len(target.AggregationRule.ClusterRoleSelectors) == 0 {
			continue
		}
		targetID := RecID(KindClusterRole, "", target.Name)
		sourceSet := make(map[RoleID]struct{})

		for _, selector := range target.AggregationRule.ClusterRoleSelectors {
			candidates, err := matchAggregationSelector(selector, labelIndex, clusterRoles)
			if err != nil {
				snapshot.Warnings = append(snapshot.Warnings, fmt.Sprintf("clusterrole/%s has invalid aggregation selector: %v", target.Name, err))

				continue
			}
			for _, c := range candidates {
				if c.Name == target.Name {
					continue
				}
				sourceSet[RecID(KindClusterRole, "", c.Name)] = struct{}{}
			}
		}

		if len(sourceSet) == 0 {
			continue
		}
		sources := make([]RoleID, 0, len(sourceSet))
		for sourceID := range sourceSet {
			sources = append(sources, sourceID)
		}
		slices.Sort(sources)
		snapshot.AggregatedRoleSources[targetID] = sources
	}
}

// matchAggregationSelector returns ClusterRoles matching a single aggregation selector.
func matchAggregationSelector(
	selector metav1.LabelSelector,
	labelIndex map[labelEntry][]*rbacv1.ClusterRole,
	allClusterRoles []*rbacv1.ClusterRole,
) ([]*rbacv1.ClusterRole, error) {
	if len(selector.MatchExpressions) == 0 && len(selector.MatchLabels) > 0 {
		return indexedCandidates(labelIndex, selector.MatchLabels), nil
	}

	labelSelector, err := metav1.LabelSelectorAsSelector(&selector)
	if err != nil {
		return nil, err
	}

	var result []*rbacv1.ClusterRole
	for _, candidate := range allClusterRoles {
		if labelSelector.Matches(labels.Set(candidate.Labels)) {
			result = append(result, candidate)
		}
	}

	return result, nil
}

// indexedCandidates returns ClusterRoles matching ALL the given matchLabels
// by intersecting per-label candidate lists from the pre-built index.
func indexedCandidates(idx map[labelEntry][]*rbacv1.ClusterRole, matchLabels map[string]string) []*rbacv1.ClusterRole {
	var result []*rbacv1.ClusterRole
	for k, v := range matchLabels {
		candidates := idx[labelEntry{k, v}]
		if result == nil {
			result = append([]*rbacv1.ClusterRole(nil), candidates...)

			continue
		}
		result = intersectByName(result, candidates)
	}

	return result
}

func intersectByName(base, filter []*rbacv1.ClusterRole) []*rbacv1.ClusterRole {
	set := make(map[string]struct{}, len(filter))
	for _, c := range filter {
		set[c.Name] = struct{}{}
	}
	filtered := base[:0]
	for _, c := range base {
		if _, ok := set[c.Name]; ok {
			filtered = append(filtered, c)
		}
	}

	return filtered
}

func indexBindingRecord(next *Snapshot, uid types.UID, kind, namespace, name string,
	roleRef rbacv1.RoleRef, subjects []rbacv1.Subject,
) {
	key := RoleRefKey{Kind: roleRef.Kind, Namespace: "", Name: roleRef.Name}
	if namespace != "" && strings.EqualFold(roleRef.Kind, KindRole) {
		key.Namespace = namespace
	}
	bindRec := &BindingRecord{
		UID:       uid,
		Kind:      kind,
		Namespace: namespace,
		Name:      name,
		RoleRef:   key,
		Subjects:  append([]rbacv1.Subject(nil), subjects...),
	}
	next.BindingsByRoleRef[key] = append(next.BindingsByRoleRef[key], bindRec)
}

func indexRoleBindings(next *Snapshot, roleBindings []*rbacv1.RoleBinding) {
	for _, binding := range roleBindings {
		indexBindingRecord(next, binding.UID, KindRoleBinding, binding.Namespace, binding.Name,
			binding.RoleRef, binding.Subjects)
	}
}

func indexClusterRoleBindings(next *Snapshot, clusterRoleBindings []*rbacv1.ClusterRoleBinding) {
	for _, binding := range clusterRoleBindings {
		indexBindingRecord(next, binding.UID, KindClusterRoleBinding, "", binding.Name,
			binding.RoleRef, binding.Subjects)
	}
}

func indexServiceAccounts(next *Snapshot, serviceAccounts []*corev1.ServiceAccount) {
	for _, sa := range serviceAccounts {
		next.ServiceAccounts[serviceAccountKey(sa.Namespace, sa.Name)] = struct{}{}
	}
}

func indexPods(next *Snapshot, pods []*corev1.Pod) {
	for _, pod := range pods {
		sa := normalizeServiceAccountName(pod.Spec.ServiceAccountName)
		key := serviceAccountKey(pod.Namespace, sa)
		next.PodsByServiceAccount[key] = append(next.PodsByServiceAccount[key], &PodRecord{
			UID:                pod.UID,
			Namespace:          pod.Namespace,
			Name:               pod.Name,
			ServiceAccountName: sa,
			Phase:              pod.Status.Phase,
			OwnerReferences:    cloneSlice(pod.OwnerReferences),
		})
	}
}

func sortSnapshot(next *Snapshot) {
	for key := range next.PodsByServiceAccount {
		sort.Slice(next.PodsByServiceAccount[key], func(i, j int) bool {
			left := next.PodsByServiceAccount[key][i]
			right := next.PodsByServiceAccount[key][j]
			if left.Namespace != right.Namespace {
				return left.Namespace < right.Namespace
			}
			if left.Name != right.Name {
				return left.Name < right.Name
			}

			return string(left.UID) < string(right.UID)
		})
	}

	slices.Sort(next.AllRoleIDs)
}
