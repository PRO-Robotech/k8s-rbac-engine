// Package policyengine evaluates RbacPolicy objects against Kubernetes Roles
// and ClusterRoles, returning one Finding per matching (policy, rule) pair.
package policyengine

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	rbacv1 "k8s.io/api/rbac/v1"

	rbacgraph "k8s-rbac-engine/pkg/apis/rbacgraph"
	"k8s-rbac-engine/pkg/apis/rbacreports/v1alpha1"
	"k8s-rbac-engine/pkg/conditions"
	"k8s-rbac-engine/pkg/indexer"
	"k8s-rbac-engine/pkg/matcher"
)

// Finding describes one PolicyRule of a role that violates one RbacPolicy.
type Finding struct {
	Policy    *v1alpha1.RbacPolicy
	RuleIndex int
	Rule      rbacv1.PolicyRule
	Message   string
}

// Evaluate runs every policy against the role, returning findings in
// policy then rule-index order.
func Evaluate(role *indexer.RoleRecord, policies []v1alpha1.RbacPolicy) []Finding {
	if role == nil {
		return nil
	}
	var findings []Finding
	for i := range policies {
		p := &policies[i]
		if !targetKindMatches(p, role.Kind) {
			continue
		}
		if isExcluded(p, role) {
			continue
		}
		for ruleIdx, rule := range role.Rules {
			if !ruleMatchesPolicy(rule, p) {
				continue
			}
			findings = append(findings, Finding{
				Policy:    p,
				RuleIndex: ruleIdx,
				Rule:      rule,
				Message:   formatMessage(role, rule),
			})
		}
	}

	return findings
}

// targetKindMatches reports whether the policy applies to the given role kind.
// Empty TargetKinds means both Role and ClusterRole.
func targetKindMatches(p *v1alpha1.RbacPolicy, roleKind string) bool {
	if len(p.Spec.TargetKinds) == 0 {
		return true
	}

	return slices.Contains(p.Spec.TargetKinds, roleKind)
}

// isExcluded reports whether the policy's exclude block excludes the role.
// Namespace and roleName patterns support trailing-"*" wildcards.
func isExcluded(p *v1alpha1.RbacPolicy, role *indexer.RoleRecord) bool {
	if matchesAnyWildcard(p.Spec.Exclude.Namespaces, role.Namespace) {
		return true
	}
	if matchesAnyWildcard(p.Spec.Exclude.RoleNames, role.Name) {
		return true
	}

	return false
}

func matchesAnyWildcard(patterns []string, s string) bool {
	for _, pat := range patterns {
		if matchWildcard(pat, s) {
			return true
		}
	}

	return false
}

// matchWildcard matches with trailing-"*" wildcard semantics (e.g. "kube-*").
// Any non-trailing "*" is treated as a literal.
func matchWildcard(pattern, s string) bool {
	if pattern == "" {
		return false
	}
	if !strings.HasSuffix(pattern, "*") {
		return pattern == s
	}
	prefix := strings.TrimSuffix(pattern, "*")

	return strings.HasPrefix(s, prefix)
}

// ruleMatchesPolicy decides whether a single PolicyRule violates a policy.
// When conditions are set, the simple-mode fields are ignored.
func ruleMatchesPolicy(rule rbacv1.PolicyRule, p *v1alpha1.RbacPolicy) bool {
	if len(p.Spec.Match.Conditions) > 0 {
		return conditions.Evaluate(rule, p.Spec.Match.Conditions)
	}

	return simpleMatch(rule, p.Spec.Match)
}

// simpleMatch returns true when rule.{resources,verbs,apiGroups} all intersect
// the policy's match block. Fails closed on empty resources or verbs.
func simpleMatch(rule rbacv1.PolicyRule, m v1alpha1.Match) bool {
	if len(m.Resources) == 0 || len(m.Verbs) == 0 {
		return false
	}

	wm := rbacgraph.WildcardModeWildcard
	if m.MatchMode == v1alpha1.MatchModeExact {
		wm = rbacgraph.WildcardModeExact
	}

	result := matcher.MatchRule(matcher.MatchInput{
		Rule: rule,
		Selector: rbacgraph.Selector{
			APIGroups: m.APIGroups,
			Resources: m.Resources,
			Verbs:     m.Verbs,
		},
		Mode:         rbacgraph.MatchModeAny,
		WildcardMode: wm,
	})

	return result.Matched
}

// formatMessage builds a human-readable violation message for a rule.
func formatMessage(role *indexer.RoleRecord, rule rbacv1.PolicyRule) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s '%s' should not have access to ", role.Kind, role.Name)

	switch {
	case len(rule.Resources) > 0:
		b.WriteString(formatResourceClause(rule.Resources))
	case len(rule.NonResourceURLs) > 0:
		b.WriteString(formatNonResourceClause(rule.NonResourceURLs))
	default:
		b.WriteString("(unknown)")
	}

	fmt.Fprintf(&b, " for verbs %s", formatList(rule.Verbs))

	if role.Kind == v1alpha1.KindRole && role.Namespace != "" {
		fmt.Fprintf(&b, " in namespace '%s'", role.Namespace)
	}

	return b.String()
}

func formatResourceClause(resources []string) string {
	sorted := append([]string(nil), resources...)
	sort.Strings(sorted)
	if len(sorted) == 1 {
		return "resource '" + sorted[0] + "'"
	}

	return "resources " + formatList(sorted)
}

func formatNonResourceClause(urls []string) string {
	sorted := append([]string(nil), urls...)
	sort.Strings(sorted)
	if len(sorted) == 1 {
		return "nonResourceURL '" + sorted[0] + "'"
	}

	return "nonResourceURLs " + formatList(sorted)
}

// formatList renders a slice as "[a, b, c]".
func formatList(items []string) string {
	return "[" + strings.Join(items, ", ") + "]"
}
