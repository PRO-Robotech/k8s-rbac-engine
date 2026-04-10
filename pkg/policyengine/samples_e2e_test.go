package policyengine_test

import (
	"os"
	"path/filepath"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/yaml"

	"k8s-rbac-engine/pkg/apis/rbacreports/v1alpha1"
	"k8s-rbac-engine/pkg/indexer"
	"k8s-rbac-engine/pkg/policyengine"
)

// loadSample reads one of the built-in samples from config/samples and
// unmarshals it into an RbacPolicy. Test fails if the file is missing or
// malformed — the sample-validation test in pkg/apis/rbacreports/v1alpha1
// catches that earlier, but we duplicate the check so a single failing
// e2e test points at the right file.
func loadSample(t *testing.T, filename string) v1alpha1.RbacPolicy {
	t.Helper()
	path := filepath.Join("..", "..", "config", "samples", filename)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var p v1alpha1.RbacPolicy
	if err := yaml.UnmarshalStrict(data, &p); err != nil {
		t.Fatalf("unmarshal %s: %v", path, err)
	}

	return p
}

// TestSamples_KSV049_FiresOnConfigmapWriter runs the built-in KSV049 policy
// against a configmap-writing role and asserts a single finding.
func TestSamples_KSV049_FiresOnConfigmapWriter(t *testing.T) {
	policy := loadSample(t, "ksv049-manage-configmaps.yaml")
	role := &indexer.RoleRecord{
		UID: types.UID("uid"), Kind: v1alpha1.KindRole,
		Namespace: "istio-system", Name: "istiod",
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{""},
			Resources: []string{"configmaps"},
			Verbs:     []string{"create", "update"},
		}},
	}

	findings := policyengine.Evaluate(role, []v1alpha1.RbacPolicy{policy})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Policy.Spec.CheckID != "KSV049" {
		t.Errorf("CheckID = %q, want KSV049", findings[0].Policy.Spec.CheckID)
	}
}

// TestSamples_KSV044_OnlyMatchesLiteralWildcard locks in the matchMode=exact
// behavior of the KSV044 sample. The role with concrete pods/get must NOT
// match; the cluster-admin role with literal "*" MUST match.
func TestSamples_KSV044_OnlyMatchesLiteralWildcard(t *testing.T) {
	policy := loadSample(t, "ksv044-wildcard-verb-and-resource.yaml")

	clusterAdmin := &indexer.RoleRecord{
		Kind: v1alpha1.KindClusterRole, Name: "cluster-admin",
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"},
		}},
	}
	if got := policyengine.Evaluate(clusterAdmin, []v1alpha1.RbacPolicy{policy}); len(got) != 1 {
		t.Errorf("KSV044 must fire on literal wildcard role; got %d findings", len(got))
	}

	narrow := &indexer.RoleRecord{
		Kind: v1alpha1.KindClusterRole, Name: "reader",
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"},
		}},
	}
	if got := policyengine.Evaluate(narrow, []v1alpha1.RbacPolicy{policy}); len(got) != 0 {
		t.Errorf("KSV044 must NOT fire on narrow role (matchMode=exact); got %d findings", len(got))
	}
}

// TestSamples_KSV045_FiresOnWildcardVerbConcreteResource exercises the
// conditions DSL form. This is the dual of KSV044: catches "all verbs on a
// specific resource" without firing on KSV044's "all verbs on all resources".
func TestSamples_KSV045_FiresOnWildcardVerbConcreteResource(t *testing.T) {
	policy := loadSample(t, "ksv045-wildcard-verb-roles.yaml")

	wildcardVerbConcreteResource := &indexer.RoleRecord{
		Kind: v1alpha1.KindClusterRole, Name: "pod-god",
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"*"},
		}},
	}
	if got := policyengine.Evaluate(wildcardVerbConcreteResource, []v1alpha1.RbacPolicy{policy}); len(got) != 1 {
		t.Errorf("KSV045 must fire when verbs=[*] and resources is concrete; got %d findings", len(got))
	}

	// Role with both wildcards: KSV044's job, NOT KSV045's. Conditions
	// in KSV045 require resources to NOT contain "*", so this is filtered.
	bothWildcard := &indexer.RoleRecord{
		Kind: v1alpha1.KindClusterRole, Name: "cluster-admin",
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"},
		}},
	}
	if got := policyengine.Evaluate(bothWildcard, []v1alpha1.RbacPolicy{policy}); len(got) != 0 {
		t.Errorf("KSV045 must NOT fire on cluster-admin (KSV044 owns that); got %d findings", len(got))
	}
}

// TestSamples_KSV050_FiresOnRBACWriter exercises the most important policy:
// roles that can mutate other roles (privilege escalation path).
func TestSamples_KSV050_FiresOnRBACWriter(t *testing.T) {
	policy := loadSample(t, "ksv050-manage-rbac.yaml")
	role := &indexer.RoleRecord{
		Kind: v1alpha1.KindClusterRole, Name: "rbac-bootstrapper",
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{"rbac.authorization.k8s.io"},
			Resources: []string{"clusterroles", "clusterrolebindings"},
			Verbs:     []string{"create", "update", "patch", "delete"},
		}},
	}
	findings := policyengine.Evaluate(role, []v1alpha1.RbacPolicy{policy})
	if len(findings) != 1 {
		t.Fatalf("KSV050 must fire on RBAC writer; got %d findings", len(findings))
	}
}

// TestSamples_KSV113_OnlyMatchesNamespacedRole confirms targetKinds=[Role]
// is honored — KSV113 (namespace secrets) must NOT fire on a ClusterRole
// even if the ClusterRole grants secret access (KSV041 owns that).
func TestSamples_KSV113_OnlyMatchesNamespacedRole(t *testing.T) {
	policy := loadSample(t, "ksv113-manage-namespace-secrets.yaml")

	namespacedRole := &indexer.RoleRecord{
		Kind: v1alpha1.KindRole, Namespace: "default", Name: "secret-reader",
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"},
		}},
	}
	if got := policyengine.Evaluate(namespacedRole, []v1alpha1.RbacPolicy{policy}); len(got) != 1 {
		t.Errorf("KSV113 must fire on Role with secret access; got %d findings", len(got))
	}

	clusterRole := &indexer.RoleRecord{
		Kind: v1alpha1.KindClusterRole, Name: "cluster-secret-reader",
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"},
		}},
	}
	if got := policyengine.Evaluate(clusterRole, []v1alpha1.RbacPolicy{policy}); len(got) != 0 {
		t.Errorf("KSV113 targetKinds=[Role] must NOT fire on ClusterRole; got %d findings", len(got))
	}
}

// TestSamples_AllPoliciesAgainstClusterAdmin is a smoke test: load all 14
// built-in samples and run them against a cluster-admin-style role with
// resources=[*] verbs=[*]. The exact set of fired policies is documented
// here so any future drift in either the samples or the engine is caught.
func TestSamples_AllPoliciesAgainstClusterAdmin(t *testing.T) {
	allPolicies := loadAllSamples(t)

	clusterAdmin := &indexer.RoleRecord{
		Kind: v1alpha1.KindClusterRole, Name: "cluster-admin",
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"},
		}},
	}

	findings := policyengine.Evaluate(clusterAdmin, allPolicies)

	// Build a set of fired CheckIDs.
	fired := make(map[string]bool)
	for _, f := range findings {
		fired[f.Policy.Spec.CheckID] = true
	}

	// Expected fires for cluster-admin (resources=[*] verbs=[*] on a ClusterRole):
	//   KSV041 — secrets ⊂ * → fires (wildcard mode)
	//   KSV044 — exact mode, literal wildcard → fires
	//   KSV046 — resources=[*] + write verbs → fires (conditions)
	//   KSV048 — pods/workloads ⊂ * → fires (twice, core+apps; coalesced into one CheckID)
	//   KSV049 — configmaps ⊂ * → fires
	//   KSV050 — rbac.authorization.k8s.io/* ⊂ * → fires
	//   KSV053 — pods/exec ⊂ * → fires
	//   KSV056 — networking ⊂ * → fires
	//   KSV114 — webhookconfigurations ⊂ * → fires
	//
	// NOT fired:
	//   KSV045 — requires resources NOT containing "*" → filtered by notContains
	//   KSV047 — requires literal "nodes/proxy" → fires only if rule contains it explicitly
	//   KSV112 — targetKinds=[Role], cluster-admin is ClusterRole
	//   KSV113 — targetKinds=[Role]
	expectedFired := []string{"KSV041", "KSV044", "KSV046", "KSV048", "KSV049", "KSV050", "KSV053", "KSV056", "KSV114"}
	expectedNotFired := []string{"KSV045", "KSV047", "KSV112", "KSV113"}

	for _, id := range expectedFired {
		if !fired[id] {
			t.Errorf("expected %s to fire on cluster-admin, but it did not", id)
		}
	}
	for _, id := range expectedNotFired {
		if fired[id] {
			t.Errorf("expected %s to NOT fire on cluster-admin, but it did", id)
		}
	}
}

func loadAllSamples(t *testing.T) []v1alpha1.RbacPolicy {
	t.Helper()
	dir := filepath.Join("..", "..", "config", "samples")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read samples dir: %v", err)
	}
	var policies []v1alpha1.RbacPolicy
	for _, e := range entries {
		if e.IsDir() || e.Name() == "kustomization.yaml" {
			continue
		}
		policies = append(policies, loadSample(t, e.Name()))
	}

	return policies
}
