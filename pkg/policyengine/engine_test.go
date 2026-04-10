package policyengine

import (
	"strings"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"

	"k8s-rbac-engine/pkg/apis/rbacreports/v1alpha1"
	"k8s-rbac-engine/pkg/conditions"
	"k8s-rbac-engine/pkg/indexer"
)

// ksv049 is the canonical "Manage configmaps" policy from the spec example
// in section 5.1. We use it across multiple tests so the message format
// can be cross-checked against the literal example string.
func ksv049() v1alpha1.RbacPolicy {
	return v1alpha1.RbacPolicy{
		Spec: v1alpha1.RbacPolicySpec{
			Severity:    v1alpha1.SeverityMedium,
			Category:    "Kubernetes Security Check",
			CheckID:     "KSV049",
			Title:       "Manage configmaps",
			Description: "Role has permission to manage configmaps.",
			Remediation: "Remove write verbs on configmaps.",
			TargetKinds: []string{v1alpha1.KindRole, v1alpha1.KindClusterRole},
			Match: v1alpha1.Match{
				MatchMode: v1alpha1.MatchModeWildcard,
				APIGroups: []string{""},
				Resources: []string{"configmaps"},
				Verbs:     []string{"create", "update", "patch", "delete"},
			},
		},
	}
}

func roleIstiod() *indexer.RoleRecord {
	return &indexer.RoleRecord{
		Kind:      v1alpha1.KindRole,
		Namespace: "istio-system",
		Name:      "istiod",
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"configmaps"},
				Verbs:     []string{"create", "update"},
			},
		},
	}
}

// TestEvaluate_SimpleMatchHits verifies an end-to-end match produces the
// expected message string.
func TestEvaluate_SimpleMatchHits(t *testing.T) {
	findings := Evaluate(roleIstiod(), []v1alpha1.RbacPolicy{ksv049()})
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	f := findings[0]
	if f.Policy.Spec.CheckID != "KSV049" {
		t.Errorf("CheckID = %q, want KSV049", f.Policy.Spec.CheckID)
	}
	if f.RuleIndex != 0 {
		t.Errorf("RuleIndex = %d, want 0", f.RuleIndex)
	}
	want := "Role 'istiod' should not have access to resource 'configmaps' for verbs [create, update] in namespace 'istio-system'"
	if f.Message != want {
		t.Errorf("Message = %q\nwant      %q", f.Message, want)
	}
}

// TestEvaluate_SimpleMatchMisses confirms a role whose rules don't intersect
// the policy fields produces no findings.
func TestEvaluate_SimpleMatchMisses(t *testing.T) {
	role := &indexer.RoleRecord{
		Kind: v1alpha1.KindRole, Namespace: "ns", Name: "reader",
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{""},
			Resources: []string{"configmaps"},
			Verbs:     []string{"get", "list"}, // read-only — no overlap
		}},
	}
	findings := Evaluate(role, []v1alpha1.RbacPolicy{ksv049()})
	if len(findings) != 0 {
		t.Fatalf("got %d findings, want 0: %+v", len(findings), findings)
	}
}

// TestEvaluate_TargetKinds_OnlyClusterRole confirms a policy targeting
// ClusterRole skips Role objects.
func TestEvaluate_TargetKinds_OnlyClusterRole(t *testing.T) {
	p := ksv049()
	p.Spec.TargetKinds = []string{v1alpha1.KindClusterRole}

	findings := Evaluate(roleIstiod(), []v1alpha1.RbacPolicy{p})
	if len(findings) != 0 {
		t.Fatalf("policy targeting ClusterRole only must skip Role; got %d findings", len(findings))
	}
}

// TestEvaluate_TargetKinds_Empty confirms empty TargetKinds applies to both kinds.
func TestEvaluate_TargetKinds_Empty(t *testing.T) {
	p := ksv049()
	p.Spec.TargetKinds = nil

	findings := Evaluate(roleIstiod(), []v1alpha1.RbacPolicy{p})
	if len(findings) != 1 {
		t.Fatalf("empty TargetKinds must apply to Role; got %d findings", len(findings))
	}
}

// TestEvaluate_Exclude_NamespaceWildcard exercises the trailing-"*" pattern.
func TestEvaluate_Exclude_NamespaceWildcard(t *testing.T) {
	tests := []struct {
		name      string
		patterns  []string
		namespace string
		excluded  bool
	}{
		{"exact-match", []string{"istio-system"}, "istio-system", true},
		{"exact-no-match", []string{"kube-system"}, "istio-system", false},
		{"trailing-star-match", []string{"kube-*"}, "kube-system", true},
		{"trailing-star-match-other", []string{"kube-*"}, "kube-public", true},
		{"trailing-star-no-match", []string{"kube-*"}, "istio-system", false},
		{"empty-patterns", nil, "istio-system", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := ksv049()
			p.Spec.Exclude.Namespaces = tt.patterns

			role := &indexer.RoleRecord{
				Kind: v1alpha1.KindRole, Namespace: tt.namespace, Name: "istiod",
				Rules: roleIstiod().Rules,
			}
			findings := Evaluate(role, []v1alpha1.RbacPolicy{p})
			gotExcluded := len(findings) == 0
			if gotExcluded != tt.excluded {
				t.Fatalf("excluded = %v, want %v", gotExcluded, tt.excluded)
			}
		})
	}
}

// TestEvaluate_Exclude_RoleNameWildcard mirrors the same pattern test for
// the roleNames exclude list.
func TestEvaluate_Exclude_RoleNameWildcard(t *testing.T) {
	tests := []struct {
		name     string
		patterns []string
		roleName string
		excluded bool
	}{
		{"exact-match", []string{"istiod"}, "istiod", true},
		{"trailing-star", []string{"system:*"}, "system:controller:bootstrap-signer", true},
		{"no-match", []string{"system:*"}, "istiod", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := ksv049()
			p.Spec.Exclude.RoleNames = tt.patterns
			role := &indexer.RoleRecord{
				Kind: v1alpha1.KindRole, Namespace: "ns", Name: tt.roleName,
				Rules: roleIstiod().Rules,
			}
			findings := Evaluate(role, []v1alpha1.RbacPolicy{p})
			gotExcluded := len(findings) == 0
			if gotExcluded != tt.excluded {
				t.Fatalf("excluded = %v, want %v", gotExcluded, tt.excluded)
			}
		})
	}
}

// TestEvaluate_MatchModeExact_FindsLiteralWildcard exercises KSV044-style
// search: find roles with literal verbs=["*"] using matchMode=exact.
func TestEvaluate_MatchModeExact_FindsLiteralWildcard(t *testing.T) {
	policy := v1alpha1.RbacPolicy{
		Spec: v1alpha1.RbacPolicySpec{
			Severity: v1alpha1.SeverityCritical, CheckID: "KSV044",
			Title: "No wildcard verb and resource roles",
			Match: v1alpha1.Match{
				MatchMode: v1alpha1.MatchModeExact,
				APIGroups: []string{"*"},
				Resources: []string{"*"},
				Verbs:     []string{"*"},
			},
		},
	}
	wildcardRole := &indexer.RoleRecord{
		Kind: v1alpha1.KindClusterRole, Name: "cluster-admin",
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"},
		}},
	}
	narrowRole := &indexer.RoleRecord{
		Kind: v1alpha1.KindClusterRole, Name: "reader",
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"},
		}},
	}

	if got := Evaluate(wildcardRole, []v1alpha1.RbacPolicy{policy}); len(got) != 1 {
		t.Errorf("wildcard role must match exact policy; got %d findings", len(got))
	}
	if got := Evaluate(narrowRole, []v1alpha1.RbacPolicy{policy}); len(got) != 0 {
		t.Errorf("narrow role must NOT match exact wildcard policy; got %d findings", len(got))
	}
}

// TestEvaluate_Conditions exercises the advanced-match path with a
// "wildcard verb on a concrete resource" recipe.
func TestEvaluate_Conditions(t *testing.T) {
	policy := v1alpha1.RbacPolicy{
		Spec: v1alpha1.RbacPolicySpec{
			Severity: v1alpha1.SeverityHigh,
			CheckID:  "CUSTOM-WILDVERB",
			Title:    "Wildcard verb on concrete resource",
			Match: v1alpha1.Match{
				// Resources/Verbs must be ignored because Conditions is set.
				Resources: []string{"shouldBeIgnored"},
				Verbs:     []string{"shouldBeIgnored"},
				Conditions: []conditions.Condition{
					{Field: conditions.FieldVerbs, Operator: conditions.OpContainsExact, Value: "*"},
					{Field: conditions.FieldResources, Operator: conditions.OpNotContains, Value: "*"},
				},
			},
		},
	}

	matching := &indexer.RoleRecord{
		Kind: v1alpha1.KindRole, Namespace: "ns", Name: "wildverb",
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"*"},
		}},
	}
	tooBroad := &indexer.RoleRecord{
		Kind: v1alpha1.KindRole, Namespace: "ns", Name: "wildall",
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"},
		}},
	}

	if got := Evaluate(matching, []v1alpha1.RbacPolicy{policy}); len(got) != 1 {
		t.Errorf("matching role must produce 1 finding; got %d", len(got))
	}
	if got := Evaluate(tooBroad, []v1alpha1.RbacPolicy{policy}); len(got) != 0 {
		t.Errorf("too-broad role (resources=*) must be filtered by notContains; got %d", len(got))
	}
}

// TestEvaluate_MultipleRulesProduceMultipleFindings confirms each matching
// rule of a role produces its own Finding (no coalescing in the engine).
func TestEvaluate_MultipleRulesProduceMultipleFindings(t *testing.T) {
	role := &indexer.RoleRecord{
		Kind: v1alpha1.KindRole, Namespace: "ns", Name: "multi",
		Rules: []rbacv1.PolicyRule{
			{APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"create"}},
			{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"}},
			{APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"delete"}},
		},
	}
	findings := Evaluate(role, []v1alpha1.RbacPolicy{ksv049()})
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2 (rule 0 and rule 2 violate; rule 1 doesn't)", len(findings))
	}
	if findings[0].RuleIndex != 0 || findings[1].RuleIndex != 2 {
		t.Errorf("rule indices = [%d, %d], want [0, 2]", findings[0].RuleIndex, findings[1].RuleIndex)
	}
}

// TestEvaluate_EmptyPolicies returns no findings.
func TestEvaluate_EmptyPolicies(t *testing.T) {
	if got := Evaluate(roleIstiod(), nil); len(got) != 0 {
		t.Fatalf("empty policies must yield 0 findings, got %d", len(got))
	}
}

// TestEvaluate_NilRole is a defensive check.
func TestEvaluate_NilRole(t *testing.T) {
	if got := Evaluate(nil, []v1alpha1.RbacPolicy{ksv049()}); got != nil {
		t.Fatalf("nil role must return nil, got %+v", got)
	}
}

// TestSimpleMatch_MalformedPolicy_NoMatch confirms that a policy with empty
// resources/verbs in simple mode never matches anything (fail-closed).
func TestSimpleMatch_MalformedPolicy_NoMatch(t *testing.T) {
	policy := v1alpha1.RbacPolicy{
		Spec: v1alpha1.RbacPolicySpec{
			CheckID: "BROKEN",
			Match: v1alpha1.Match{
				MatchMode: v1alpha1.MatchModeWildcard,
				APIGroups: []string{""}, // resources and verbs intentionally omitted
			},
		},
	}
	role := &indexer.RoleRecord{
		Kind: v1alpha1.KindRole, Namespace: "ns", Name: "any",
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"*"},
		}},
	}
	if got := Evaluate(role, []v1alpha1.RbacPolicy{policy}); len(got) != 0 {
		t.Fatalf("malformed policy must not match anything; got %d findings", len(got))
	}
}

// TestFormatMessage_ClusterRole confirms the message format omits the
// namespace clause for ClusterRole.
func TestFormatMessage_ClusterRole(t *testing.T) {
	role := &indexer.RoleRecord{
		Kind: v1alpha1.KindClusterRole, Name: "cluster-admin",
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get", "list"},
		}},
	}
	policy := ksv049()
	policy.Spec.Match.Resources = []string{"secrets"}
	policy.Spec.Match.Verbs = []string{"get"}

	findings := Evaluate(role, []v1alpha1.RbacPolicy{policy})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	msg := findings[0].Message
	if strings.Contains(msg, "in namespace") {
		t.Errorf("ClusterRole message must not contain 'in namespace'; got %q", msg)
	}
	if !strings.HasPrefix(msg, "ClusterRole 'cluster-admin'") {
		t.Errorf("message must start with kind/name; got %q", msg)
	}
}

// TestFormatMessage_NonResourceURL confirms the message format adapts when
// the offending rule grants a non-resource URL instead of resources.
func TestFormatMessage_NonResourceURL(t *testing.T) {
	policy := v1alpha1.RbacPolicy{
		Spec: v1alpha1.RbacPolicySpec{
			CheckID: "CUSTOM-METRICS",
			Match: v1alpha1.Match{
				Conditions: []conditions.Condition{
					{Field: conditions.FieldVerbs, Operator: conditions.OpContainsAny, Values: []string{"get"}},
				},
			},
		},
	}
	role := &indexer.RoleRecord{
		Kind: v1alpha1.KindClusterRole, Name: "metrics-reader",
		Rules: []rbacv1.PolicyRule{{
			NonResourceURLs: []string{"/metrics"},
			Verbs:           []string{"get"},
		}},
	}

	findings := Evaluate(role, []v1alpha1.RbacPolicy{policy})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if !strings.Contains(findings[0].Message, "nonResourceURL '/metrics'") {
		t.Errorf("message must mention nonResourceURL; got %q", findings[0].Message)
	}
}
