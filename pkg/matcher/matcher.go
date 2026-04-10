package matcher

import (
	"strings"

	rbacv1 "k8s.io/api/rbac/v1"

	api "k8s-rbac-engine/pkg/apis/rbacgraph"
)

type MatchResult struct {
	Matched  bool
	RuleRefs []api.RuleRef
}

type MatchInput struct {
	Rule         rbacv1.PolicyRule
	Selector     api.Selector
	Mode         api.MatchMode
	WildcardMode api.WildcardMode
	SourceUID    string
	RuleIndex    int
}

//nolint:gocyclo // matching logic handles resource + non-resource + combined cases
func MatchRule(in MatchInput) MatchResult {
	in.Mode = normalizeMode(in.Mode)
	in.WildcardMode = normalizeWildcardMode(in.WildcardMode)
	resourceQuery := len(in.Selector.Resources) > 0 || len(in.Selector.APIGroups) > 0 || len(in.Selector.ResourceNames) > 0
	nonResourceQuery := len(in.Selector.NonResourceURLs) > 0

	resourceRefs, resourceMatched := matchResourceRule(in)
	nonResourceRefs, nonResourceMatched := matchNonResourceRule(in)

	switch {
	case resourceQuery && nonResourceQuery:
		if resourceMatched && nonResourceMatched {
			return MatchResult{Matched: true, RuleRefs: append(resourceRefs, nonResourceRefs...)}
		}

		return MatchResult{}
	case resourceQuery:
		if resourceMatched {
			return MatchResult{Matched: true, RuleRefs: resourceRefs}
		}

		return MatchResult{}
	case nonResourceQuery:
		if nonResourceMatched {
			return MatchResult{Matched: true, RuleRefs: nonResourceRefs}
		}

		return MatchResult{}
	default:
		if resourceMatched {
			return MatchResult{Matched: true, RuleRefs: resourceRefs}
		}
		if nonResourceMatched {
			return MatchResult{Matched: true, RuleRefs: nonResourceRefs}
		}

		return MatchResult{}
	}
}

func matchResourceRule(in MatchInput) ([]api.RuleRef, bool) {
	if len(in.Rule.Resources) == 0 {
		return nil, false
	}

	isExact := in.WildcardMode == api.WildcardModeExact

	var groupFn, verbFn, resFn func(string, string) bool
	if isExact {
		groupFn = exactMatchCI
		resFn = exactMatchCI
		verbFn = exactMatchCI
	} else {
		groupFn = exactOrWildcard
		resFn = resourceWildcardMatch
		verbFn = exactOrWildcard
	}

	groupsRequested := ensureWildcardForMode(in.Selector.APIGroups, isExact)
	resourcesRequested := ensureWildcardForMode(in.Selector.Resources, isExact)
	verbsRequested := ensureWildcardForMode(in.Selector.Verbs, isExact)

	// nil = no constraint in exact mode → use all rule values directly
	var ok bool
	if groupsRequested, ok = resolveField(groupsRequested, in.Rule.APIGroups, in.Selector.APIGroups, in.Mode, groupFn); !ok {
		return nil, false
	}
	if resourcesRequested, ok = resolveField(resourcesRequested, in.Rule.Resources, in.Selector.Resources, in.Mode, resFn); !ok {
		return nil, false
	}
	if verbsRequested, ok = resolveField(verbsRequested, in.Rule.Verbs, in.Selector.Verbs, in.Mode, verbFn); !ok {
		return nil, false
	}

	if !matchResourceNames(in.Selector.ResourceNames, in.Rule.ResourceNames, in.Mode) {
		return nil, false
	}

	// Only include resourceNames in the RuleRef when the rule itself restricts
	// by name. When the rule has no name restriction (= all names allowed),
	// leave empty to avoid echoing the query's resourceNames as if the role
	// specifically grants access to those names.
	var ruleRefNames []string
	if len(in.Rule.ResourceNames) > 0 {
		ruleRefNames = copyStrings(in.Selector.ResourceNames)
	}

	refs := make([]api.RuleRef, 0, len(groupsRequested)*len(resourcesRequested)*len(verbsRequested))
	for _, g := range groupsRequested {
		for _, r := range resourcesRequested {
			resource, subresource := splitResource(r)
			for _, v := range verbsRequested {
				refs = append(refs, api.RuleRef{
					APIGroup:        g,
					Resource:        resource,
					Subresource:     subresource,
					Verb:            v,
					ResourceNames:   ruleRefNames,
					SourceObjectUID: in.SourceUID,
					SourceRuleIndex: in.RuleIndex,
				})
			}
		}
	}

	return refs, true
}

func matchNonResourceRule(in MatchInput) ([]api.RuleRef, bool) {
	if len(in.Rule.NonResourceURLs) == 0 {
		return nil, false
	}

	isExact := in.WildcardMode == api.WildcardModeExact

	var urlFn, verbFn func(string, string) bool
	if isExact {
		urlFn = nonResourceExactMatch
		verbFn = exactMatchCI
	} else {
		urlFn = nonResourceWildcardMatch
		verbFn = exactOrWildcard
	}

	requestedURLs := ensureWildcardForMode(in.Selector.NonResourceURLs, isExact)
	var ok bool
	if requestedURLs, ok = resolveField(requestedURLs, in.Rule.NonResourceURLs, in.Selector.NonResourceURLs, in.Mode, urlFn); !ok {
		return nil, false
	}

	verbsRequested := ensureWildcardForMode(in.Selector.Verbs, isExact)
	if verbsRequested, ok = resolveField(verbsRequested, in.Rule.Verbs, in.Selector.Verbs, in.Mode, verbFn); !ok {
		return nil, false
	}

	refs := make([]api.RuleRef, 0, len(requestedURLs)*len(verbsRequested))
	for _, url := range requestedURLs {
		for _, v := range verbsRequested {
			refs = append(refs, api.RuleRef{
				NonResourceURLs: []string{url},
				Verb:            v,
				SourceObjectUID: in.SourceUID,
				SourceRuleIndex: in.RuleIndex,
			})
		}
	}

	return refs, true
}

func matchRequested(requested, allowed []string, mode api.MatchMode, fn func(string, string) bool) []string {
	if len(requested) == 0 {
		requested = []string{"*"}
	}
	if len(allowed) == 0 {
		return nil
	}

	matches := make([]string, 0, len(requested))
	for _, req := range requested {
		ok := false
		for _, allow := range allowed {
			if fn(req, allow) {
				ok = true

				break
			}
		}
		if ok {
			matches = append(matches, req)

			continue
		}
		if mode == api.MatchModeAll {
			return nil
		}
	}

	if mode == api.MatchModeAny && len(matches) == 0 {
		return nil
	}

	return matches
}

func exactMatchCI(requested, allowed string) bool {
	return strings.TrimSpace(strings.ToLower(requested)) == strings.TrimSpace(strings.ToLower(allowed))
}

func nonResourceExactMatch(requested, allowed string) bool {
	return strings.TrimSpace(requested) == strings.TrimSpace(allowed)
}

func exactOrWildcard(requested, allowed string) bool {
	r := strings.TrimSpace(strings.ToLower(requested))
	a := strings.TrimSpace(strings.ToLower(allowed))

	return a == "*" || r == "*" || r == a
}

func resourceWildcardMatch(requested, allowed string) bool {
	r := strings.TrimSpace(strings.ToLower(requested))
	a := strings.TrimSpace(strings.ToLower(allowed))
	if a == "*" || r == "*" {
		return true
	}
	if r == a {
		return true
	}
	if prefix, ok := strings.CutSuffix(a, "/*"); ok {
		return strings.HasPrefix(r, prefix+"/")
	}

	return false
}

func nonResourceWildcardMatch(requested, allowed string) bool {
	r := strings.TrimSpace(requested)
	a := strings.TrimSpace(allowed)
	if a == "*" || r == "*" {
		return true
	}
	if r == a {
		return true
	}
	if prefix, ok := strings.CutSuffix(a, "*"); ok {
		return strings.HasPrefix(r, prefix)
	}

	return false
}

func matchResourceNames(requested, allowed []string, mode api.MatchMode) bool {
	if len(requested) == 0 {
		return true
	}
	if len(allowed) == 0 {
		return true
	}
	lookup := make(map[string]struct{}, len(allowed))
	for _, name := range allowed {
		lookup[name] = struct{}{}
	}
	if mode == api.MatchModeAll {
		for _, name := range requested {
			if _, ok := lookup[name]; !ok {
				return false
			}
		}

		return true
	}
	for _, name := range requested {
		if _, ok := lookup[name]; ok {
			return true
		}
	}

	return false
}

func splitResource(resource string) (base, subresource string) {
	parts := strings.SplitN(resource, "/", 2)
	if len(parts) == 1 {
		return parts[0], ""
	}

	return parts[0], parts[1]
}

// ensureWildcardForMode returns the appropriate default when values is empty.
// In wildcard mode: empty → ["*"] (match everything via wildcard expansion).
// In exact mode: empty → nil (no constraint — skip filtering on this field).
func ensureWildcardForMode(values []string, exact bool) []string {
	if len(values) == 0 {
		if exact {
			return nil
		}

		return []string{"*"}
	}

	return values
}

func copyStrings(src []string) []string {
	return append([]string(nil), src...)
}

func resolveField(requested []string, ruleValues []string, selectorValues []string,
	mode api.MatchMode, fn func(string, string) bool,
) ([]string, bool) {
	if requested != nil {
		matches := matchRequested(requested, ruleValues, mode, fn)
		if len(matches) == 0 {
			return nil, false
		}
		if len(selectorValues) == 0 {
			return copyStrings(ruleValues), true
		}

		return matches, true
	}

	return copyStrings(ruleValues), true
}

func normalizeMode(mode api.MatchMode) api.MatchMode {
	if mode == api.MatchModeAll {
		return api.MatchModeAll
	}

	return api.MatchModeAny
}

func normalizeWildcardMode(wm api.WildcardMode) api.WildcardMode {
	if wm == api.WildcardModeExact {
		return api.WildcardModeExact
	}

	return api.WildcardModeWildcard
}
