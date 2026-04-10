package rolepermissionsview

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/registry/rest"

	"k8s-rbac-engine/pkg/apis/rbacgraph"
	"k8s-rbac-engine/pkg/engine"
	"k8s-rbac-engine/pkg/indexer"
)

const coreAPIGroupDisplay = "core"

type REST struct {
	indexer      *indexer.Indexer
	reportLookup engine.ReportLookup
}

var _ rest.Storage = &REST{}
var _ rest.Creater = &REST{}
var _ rest.SingularNameProvider = &REST{}

// NewREST returns a REST handler for rolepermissionsviews.
func NewREST(idx *indexer.Indexer, reportLookup engine.ReportLookup) *REST {
	return &REST{indexer: idx, reportLookup: reportLookup}
}

func (r *REST) New() runtime.Object {
	return &rbacgraph.RolePermissionsView{}
}

func (r *REST) Destroy() {}

func (r *REST) NamespaceScoped() bool {
	return false
}

func (r *REST) GetSingularName() string {
	return "rolepermissionsview"
}

func (r *REST) Create(_ context.Context, obj runtime.Object, _ rest.ValidateObjectFunc, _ *metav1.CreateOptions) (runtime.Object, error) {
	view, ok := obj.(*rbacgraph.RolePermissionsView)
	if !ok {
		return nil, fmt.Errorf("unexpected object type: %T", obj)
	}

	spec := &view.Spec
	if spec.Role.Name == "" {
		return nil, apierrors.NewBadRequest("spec.role.name is required")
	}

	var idxKind string
	var scope rbacgraph.RoleScope
	switch strings.ToLower(string(spec.Role.Kind)) {
	case "clusterrole":
		idxKind = indexer.KindClusterRole
		scope = rbacgraph.RoleScopeCluster
	case "role":
		if spec.Role.Namespace == "" {
			return nil, apierrors.NewBadRequest("spec.role.namespace is required for role kind")
		}
		idxKind = indexer.KindRole
		scope = rbacgraph.RoleScopeNamespace
	default:
		return nil, apierrors.NewBadRequest(fmt.Sprintf(
			"spec.role.kind must be %q or %q, got %q",
			rbacgraph.RoleRefKindClusterRole, rbacgraph.RoleRefKindRole, spec.Role.Kind))
	}

	applySpecDefaults(spec)
	if spec.WildcardMode != rbacgraph.WildcardModeWildcard && spec.WildcardMode != rbacgraph.WildcardModeExact {
		return nil, apierrors.NewBadRequest(fmt.Sprintf("invalid wildcardMode %q", spec.WildcardMode))
	}

	snapshot := r.indexer.Snapshot()
	roleID := indexer.RecID(idxKind, spec.Role.Namespace, spec.Role.Name)
	role, found := snapshot.RolesByID[roleID]
	if !found {
		return nil, apierrors.NewNotFound(
			schema.GroupResource{Group: "rbac.authorization.k8s.io", Resource: strings.ToLower(idxKind) + "s"},
			spec.Role.Name,
		)
	}

	discovery := r.indexer.DiscoveryCache()
	view.Status = buildStatus(role, scope, spec, discovery)
	if r.reportLookup != nil {
		view.Status.Assessment = r.reportLookup.Lookup(role.Kind, role.Namespace, role.Name)
	}
	view.CreationTimestamp = metav1.Now()

	return view, nil
}

type resourceKey struct {
	apiGroup string
	resource string
}

func applySpecDefaults(spec *rbacgraph.RolePermissionsViewSpec) {
	if spec.MatchMode == "" {
		spec.MatchMode = rbacgraph.MatchModeAny
	}

	switch spec.WildcardMode {
	case "":
		spec.WildcardMode = rbacgraph.WildcardModeWildcard
	case "expand":
		spec.WildcardMode = rbacgraph.WildcardModeWildcard
	}
}

// verbGrant tracks which rule index granted a verb.
type verbGrant struct {
	ruleIndex int
}

// buildStatus builds the RolePermissionsViewStatus from a role's rules.
//
//nolint:gocognit,gocyclo,nestif // multi-level wildcard expansion + selector filtering in one pass
func buildStatus(
	role *indexer.RoleRecord,
	scope rbacgraph.RoleScope,
	spec *rbacgraph.RolePermissionsViewSpec,
	discovery *indexer.APIDiscoveryCache,
) rbacgraph.RolePermissionsViewStatus {
	resourceVerbs := make(map[resourceKey]map[string][]verbGrant)
	urlVerbs := make(map[string]map[string][]verbGrant)

	hasSelector := hasSelectorFilter(spec.Selector)
	expandWildcards := spec.WildcardMode != rbacgraph.WildcardModeExact

	resourceSelectorActive := len(spec.Selector.APIGroups) > 0 ||
		len(spec.Selector.Resources) > 0 ||
		len(spec.Selector.Verbs) > 0 ||
		len(spec.Selector.ResourceNames) > 0
	urlSelectorActive := len(spec.Selector.NonResourceURLs) > 0
	skipNonResourceRules := hasSelector && resourceSelectorActive && !urlSelectorActive
	skipResourceRules := hasSelector && urlSelectorActive && !resourceSelectorActive

	for ruleIdx, rule := range role.Rules {
		grant := verbGrant{ruleIndex: ruleIdx}

		if len(rule.Resources) > 0 && !skipResourceRules {
			groups := expandGroups(rule.APIGroups, discovery, expandWildcards)
			for _, group := range groups {
				resources := expandResources(group, rule.Resources, discovery, expandWildcards)
				for _, res := range resources {
					if spec.FilterPhantomAPIs && isPhantomResource(discovery, group, res) {
						continue
					}
					verbs := expandVerbs(group, res, rule.Verbs, discovery, expandWildcards)
					if hasSelector && !matchesSelector(group, res, verbs, spec.Selector, spec.MatchMode) {
						continue
					}

					emittedVerbs := verbs
					if hasSelector && len(spec.Selector.Verbs) > 0 {
						emittedVerbs = intersectVerbs(verbs, spec.Selector.Verbs)
						if len(emittedVerbs) == 0 {
							continue
						}
					}

					key := resourceKey{apiGroup: group, resource: res}
					if resourceVerbs[key] == nil {
						resourceVerbs[key] = make(map[string][]verbGrant)
					}
					for _, v := range emittedVerbs {
						resourceVerbs[key][v] = appendGrant(resourceVerbs[key][v], grant)
					}
				}
			}
		}

		if len(rule.NonResourceURLs) == 0 || skipNonResourceRules {
			continue
		}
		filterURLs := hasSelector && len(spec.Selector.NonResourceURLs) > 0
		for _, url := range rule.NonResourceURLs {
			if filterURLs && !nonResourceURLCovers(url, spec.Selector.NonResourceURLs, expandWildcards) {
				continue
			}
			if urlVerbs[url] == nil {
				urlVerbs[url] = make(map[string][]verbGrant)
			}
			for _, v := range rule.Verbs {
				urlVerbs[url][v] = appendGrant(urlVerbs[url][v], grant)
			}
		}
	}

	return rbacgraph.RolePermissionsViewStatus{
		Name:            role.Name,
		Scope:           scope,
		APIGroups:       buildAPIGroups(resourceVerbs, role, discovery),
		NonResourceURLs: buildNonResourceURLs(urlVerbs, role),
	}
}

func appendGrant(grants []verbGrant, g verbGrant) []verbGrant {
	for _, existing := range grants {
		if existing.ruleIndex == g.ruleIndex {
			return grants
		}
	}

	return append(grants, g)
}

func expandGroups(apiGroups []string, discovery *indexer.APIDiscoveryCache, expandWildcards bool) []string {
	if !expandWildcards || discovery == nil || !slices.Contains(apiGroups, "*") {
		return apiGroups
	}
	groups := make([]string, 0, len(discovery.ResourcesByGroup))
	for g := range discovery.ResourcesByGroup {
		groups = append(groups, g)
	}
	slices.Sort(groups)

	return groups
}

func expandResources(apiGroup string, resources []string, discovery *indexer.APIDiscoveryCache, expandWildcards bool) []string {
	if !expandWildcards || discovery == nil || !slices.Contains(resources, "*") {
		return resources
	}
	groupResources := discovery.ResourcesByGroup[apiGroup]
	if len(groupResources) == 0 {
		return nil
	}
	out := make([]string, 0, len(groupResources))
	for r := range groupResources {
		out = append(out, r)
	}
	slices.Sort(out)

	return out
}

func expandVerbs(apiGroup, resource string, verbs []string, discovery *indexer.APIDiscoveryCache, expandWildcards bool) []string {
	if !expandWildcards || discovery == nil || !slices.Contains(verbs, "*") {
		return verbs
	}
	groupVerbs, ok := discovery.VerbsByGroupResource[apiGroup]
	if !ok {
		return verbs
	}
	supported, ok := groupVerbs[resource]
	if !ok {
		return verbs
	}

	return supported
}

func hasSelectorFilter(sel rbacgraph.Selector) bool {
	return len(sel.APIGroups) > 0 || len(sel.Resources) > 0 || len(sel.Verbs) > 0 ||
		len(sel.ResourceNames) > 0 || len(sel.NonResourceURLs) > 0
}

func matchesSelector(apiGroup, resource string, verbs []string, sel rbacgraph.Selector, mode rbacgraph.MatchMode) bool {
	if len(sel.APIGroups) > 0 && !containsCI(sel.APIGroups, apiGroup) {
		return false
	}
	if len(sel.Resources) > 0 && !containsCI(sel.Resources, resource) {
		return false
	}

	return matchesVerbSelector(verbs, sel.Verbs, mode)
}

func matchesVerbSelector(verbs, selectorVerbs []string, mode rbacgraph.MatchMode) bool {
	if len(selectorVerbs) == 0 {
		return true
	}
	if mode == rbacgraph.MatchModeAll {
		for _, sv := range selectorVerbs {
			if !containsCI(verbs, sv) {
				return false
			}
		}

		return true
	}
	for _, sv := range selectorVerbs {
		if containsCI(verbs, sv) {
			return true
		}
	}

	return false
}

// intersectVerbs returns the subset of ruleVerbs that appear in selectorVerbs
// (case-insensitive). Order follows ruleVerbs so output stays stable.
func intersectVerbs(ruleVerbs, selectorVerbs []string) []string {
	out := make([]string, 0, len(ruleVerbs))
	for _, v := range ruleVerbs {
		if containsCI(selectorVerbs, v) {
			out = append(out, v)
		}
	}

	return out
}

// nonResourceURLCovers checks whether ruleURL covers any of the selectorURLs.
func nonResourceURLCovers(ruleURL string, selectorURLs []string, expandWildcards bool) bool {
	r := strings.TrimSpace(ruleURL)
	for _, sel := range selectorURLs {
		s := strings.TrimSpace(sel)
		if r == s {
			return true
		}
		if !expandWildcards {
			continue
		}
		if r == "*" || s == "*" {
			return true
		}
		if prefix, ok := strings.CutSuffix(r, "*"); ok && strings.HasPrefix(s, prefix) {
			return true
		}
	}

	return false
}

func containsCI(haystack []string, needle string) bool {
	n := strings.ToLower(needle)
	for _, h := range haystack {
		if strings.EqualFold(h, n) {
			return true
		}
	}

	return false
}

func buildAPIGroups(resourceVerbs map[resourceKey]map[string][]verbGrant, role *indexer.RoleRecord, discovery *indexer.APIDiscoveryCache) []rbacgraph.APIGroupPermissions {
	groupMap := make(map[string][]rbacgraph.ResourcePermissions)
	for key, verbs := range resourceVerbs {
		verbPerms := make(map[string]rbacgraph.VerbPermission, len(verbs))
		for v, grants := range verbs {
			verbPerms[v] = rbacgraph.VerbPermission{
				Granted:        true,
				SupportedByAPI: isVerbSupported(discovery, key.apiGroup, key.resource, v),
				Rules:          grantsToRules(grants, role),
			}
		}
		groupMap[key.apiGroup] = append(groupMap[key.apiGroup], rbacgraph.ResourcePermissions{
			Plural:  key.resource,
			Phantom: isPhantomResource(discovery, key.apiGroup, key.resource),
			Verbs:   verbPerms,
		})
	}

	groups := make([]rbacgraph.APIGroupPermissions, 0, len(groupMap))
	for apiGroup, resources := range groupMap {
		slices.SortFunc(resources, func(a, b rbacgraph.ResourcePermissions) int {
			return cmp.Compare(a.Plural, b.Plural)
		})
		displayGroup := apiGroup
		if displayGroup == "" {
			displayGroup = coreAPIGroupDisplay
		}
		groups = append(groups, rbacgraph.APIGroupPermissions{
			APIGroup:       displayGroup,
			ResourcesCount: len(resources),
			Resources:      resources,
		})
	}
	slices.SortFunc(groups, func(a, b rbacgraph.APIGroupPermissions) int {
		return cmp.Compare(a.APIGroup, b.APIGroup)
	})

	return groups
}

func buildNonResourceURLs(urlVerbs map[string]map[string][]verbGrant, role *indexer.RoleRecord) *rbacgraph.NonResourceURLPermissions {
	if len(urlVerbs) == 0 {
		return nil
	}
	urls := make([]rbacgraph.NonResourceURLPermissionEntry, 0, len(urlVerbs))
	for url, verbs := range urlVerbs {
		verbPerms := make(map[string]rbacgraph.VerbPermission, len(verbs))
		for v, grants := range verbs {
			verbPerms[v] = rbacgraph.VerbPermission{
				Granted:        true,
				SupportedByAPI: true,
				Rules:          grantsToRules(grants, role),
			}
		}
		urls = append(urls, rbacgraph.NonResourceURLPermissionEntry{
			URL:   url,
			Verbs: verbPerms,
		})
	}
	slices.SortFunc(urls, func(a, b rbacgraph.NonResourceURLPermissionEntry) int {
		return cmp.Compare(a.URL, b.URL)
	})

	return &rbacgraph.NonResourceURLPermissions{
		URLsCount: len(urls),
		URLs:      urls,
	}
}

func grantsToRules(grants []verbGrant, role *indexer.RoleRecord) []rbacgraph.GrantingRule {
	rules := make([]rbacgraph.GrantingRule, 0, len(grants))
	for _, g := range grants {
		r := role.Rules[g.ruleIndex]
		rules = append(rules, rbacgraph.GrantingRule{
			RuleIndex:       g.ruleIndex,
			APIGroups:       r.APIGroups,
			Resources:       r.Resources,
			Verbs:           r.Verbs,
			NonResourceURLs: r.NonResourceURLs,
		})
	}

	return rules
}

func isPhantomResource(discovery *indexer.APIDiscoveryCache, apiGroup, resource string) bool {
	if discovery == nil || resource == "*" || apiGroup == "*" {
		return false
	}
	groupResources, groupExists := discovery.ResourcesByGroup[apiGroup]
	if !groupExists {
		return true // entire API group missing from cluster
	}
	if _, resourceExists := groupResources[resource]; resourceExists {
		return false
	}
	if base, _, hasSub := strings.Cut(resource, "/"); hasSub {
		if _, baseExists := groupResources[base]; baseExists {
			return false
		}
	}

	return true
}

func isVerbSupported(discovery *indexer.APIDiscoveryCache, apiGroup, resource, verb string) bool {
	if discovery == nil {
		return true
	}
	groupVerbs, ok := discovery.VerbsByGroupResource[apiGroup]
	if !ok {
		return true
	}
	supported, ok := groupVerbs[resource]
	if !ok {
		return true
	}
	for _, v := range supported {
		if strings.EqualFold(v, verb) {
			return true
		}
	}

	return false
}
