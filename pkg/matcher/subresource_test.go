package matcher

import (
	"slices"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"

	api "k8s-rbac-engine/pkg/apis/rbacgraph"
)

// Rule `pods` must not match selector `pods/exec`: the authorizer treats a
// subresource as a separate resource from its base.
func TestMatchRule_BaseResourceDoesNotImplicitlyGrantSubresource(t *testing.T) {
	rule := rbacv1.PolicyRule{
		APIGroups: []string{""},
		Resources: []string{"pods"},
		Verbs:     []string{"get"},
	}
	sel := api.Selector{
		APIGroups: []string{""},
		Resources: []string{"pods/exec"},
		Verbs:     []string{"get"},
	}

	result := MatchRule(MatchInput{Rule: rule, Selector: sel, Mode: api.MatchModeAny, SourceUID: "u"})
	if result.Matched {
		t.Fatalf("rule on base 'pods' should NOT match selector 'pods/exec' (k8s authorizer treats them as separate resources)")
	}
}

// Rule `pods/exec` must not grant base `pods`.
func TestMatchRule_SubresourceRuleDoesNotGrantBase(t *testing.T) {
	rule := rbacv1.PolicyRule{
		APIGroups: []string{""},
		Resources: []string{"pods/exec"},
		Verbs:     []string{"create"},
	}
	sel := api.Selector{
		APIGroups: []string{""},
		Resources: []string{"pods"},
		Verbs:     []string{"create"},
	}

	result := MatchRule(MatchInput{Rule: rule, Selector: sel, Mode: api.MatchModeAny, SourceUID: "u"})
	if result.Matched {
		t.Fatalf("rule on subresource 'pods/exec' should NOT match selector 'pods'")
	}
}

// Rule `pods/log` must not grant `pods/exec`.
func TestMatchRule_DifferentSubresourcesDoNotMatch(t *testing.T) {
	rule := rbacv1.PolicyRule{
		APIGroups: []string{""},
		Resources: []string{"pods/log"},
		Verbs:     []string{"get"},
	}
	sel := api.Selector{
		APIGroups: []string{""},
		Resources: []string{"pods/exec"},
		Verbs:     []string{"get"},
	}

	result := MatchRule(MatchInput{Rule: rule, Selector: sel, Mode: api.MatchModeAny, SourceUID: "u"})
	if result.Matched {
		t.Fatalf("rule on pods/log should NOT match selector pods/exec")
	}
}

// Rule `pods/*` matches any pods subresource selector.
func TestMatchRule_SubresourceWildcardExpansion(t *testing.T) {
	rule := rbacv1.PolicyRule{
		APIGroups: []string{""},
		Resources: []string{"pods/*"},
		Verbs:     []string{"get"},
	}
	for _, subresource := range []string{"pods/exec", "pods/log", "pods/portforward"} {
		t.Run(subresource, func(t *testing.T) {
			sel := api.Selector{
				APIGroups: []string{""},
				Resources: []string{subresource},
				Verbs:     []string{"get"},
			}
			result := MatchRule(MatchInput{Rule: rule, Selector: sel, Mode: api.MatchModeAny, SourceUID: "u"})
			if !result.Matched {
				t.Fatalf("rule pods/* should match selector %s", subresource)
			}
			if len(result.RuleRefs) == 0 {
				t.Fatalf("expected non-empty ruleRefs")
			}
			ref := result.RuleRefs[0]
			if ref.Resource != "pods" || ref.Subresource != subresource[len("pods/"):] {
				t.Errorf("expected resource=pods subresource=%s, got %+v", subresource[len("pods/"):], ref)
			}
		})
	}
}

// Rule `*` resources matches a subresource selector at the matcher layer;
// phantom-filtering is the engine's separate concern.
func TestMatchRule_FullWildcardMatchesSubresourceSelector(t *testing.T) {
	rule := rbacv1.PolicyRule{
		APIGroups: []string{"", "metrics.k8s.io"},
		Resources: []string{"*"},
		Verbs:     []string{"get"},
	}
	sel := api.Selector{
		Resources: []string{"pods/exec"},
	}

	result := MatchRule(MatchInput{Rule: rule, Selector: sel, Mode: api.MatchModeAny, SourceUID: "u"})
	if !result.Matched {
		t.Fatalf("rule with resources=[*] should match any selector resource")
	}
	if len(result.RuleRefs) != 2 {
		t.Fatalf("expected 2 refs (one per apiGroup), got %d: %+v", len(result.RuleRefs), result.RuleRefs)
	}
	for _, ref := range result.RuleRefs {
		if ref.Resource != "pods" || ref.Subresource != "exec" {
			t.Errorf("expected resource=pods subresource=exec, got %+v", ref)
		}
	}
}

// In exact mode, rule `*` does not match selector `pods/exec`.
func TestMatchRule_ExactMode_FullWildcardDoesNotMatchSubresource(t *testing.T) {
	rule := rbacv1.PolicyRule{
		APIGroups: []string{""},
		Resources: []string{"*"},
		Verbs:     []string{"get"},
	}
	sel := api.Selector{
		APIGroups: []string{""},
		Resources: []string{"pods/exec"},
		Verbs:     []string{"get"},
	}

	result := MatchRule(MatchInput{Rule: rule, Selector: sel, Mode: api.MatchModeAny, WildcardMode: api.WildcardModeExact, SourceUID: "u"})
	if result.Matched {
		t.Fatalf("exact mode: rule resources=[*] should NOT match concrete selector 'pods/exec'")
	}
}

// A rule with resourceNames matches a selector that sets none, but the output
// ref drops resourceNames — so the ref looks broader than the rule.
func TestMatchRule_RuleResourceNamesHiddenWhenSelectorEmpty(t *testing.T) {
	rule := rbacv1.PolicyRule{
		APIGroups:     []string{""},
		Resources:     []string{"configmaps"},
		ResourceNames: []string{"my-config"},
		Verbs:         []string{"get"},
	}
	sel := api.Selector{
		APIGroups: []string{""},
		Resources: []string{"configmaps"},
		Verbs:     []string{"get"},
		// ResourceNames: empty — no constraint
	}

	result := MatchRule(MatchInput{Rule: rule, Selector: sel, Mode: api.MatchModeAny, SourceUID: "u"})
	if !result.Matched {
		t.Fatal("expected match (selector has no resourceName constraint)")
	}
	if len(result.RuleRefs) == 0 {
		t.Fatal("expected non-empty refs")
	}

	// Current behavior: ResourceNames in output is empty, hiding the rule's restriction.
	for _, ref := range result.RuleRefs {
		if len(ref.ResourceNames) != 0 {
			t.Logf("output ref shows ResourceNames=%v — review whether this should echo the rule's restriction", ref.ResourceNames)
		}
	}
}

// Any-mode match on resourceNames echoes the whole selector list back: rule
// allows [a,b], selector [b,d] matches, but the ref carries [b,d] — including
// the ungranted `d`.
func TestMatchRule_ResourceNamesEchoesUnmatchedSelectorNames(t *testing.T) {
	rule := rbacv1.PolicyRule{
		APIGroups:     []string{""},
		Resources:     []string{"configmaps"},
		ResourceNames: []string{"a", "b"},
		Verbs:         []string{"get"},
	}
	sel := api.Selector{
		APIGroups:     []string{""},
		Resources:     []string{"configmaps"},
		ResourceNames: []string{"b", "d"},
		Verbs:         []string{"get"},
	}

	result := MatchRule(MatchInput{Rule: rule, Selector: sel, Mode: api.MatchModeAny, SourceUID: "u"})
	if !result.Matched {
		t.Fatal("expected match (b is in rule's allowed list)")
	}
	if len(result.RuleRefs) == 0 {
		t.Fatal("expected non-empty refs")
	}

	// Current behavior — output ref includes 'd' which the rule does NOT grant.
	for _, ref := range result.RuleRefs {
		if slices.Contains(ref.ResourceNames, "d") {
			t.Logf("output ref includes resourceName 'd' even though rule doesn't grant it — review semantics: %+v", ref.ResourceNames)
		}
	}
}
