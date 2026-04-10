package v1alpha1_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"

	"k8s-rbac-engine/pkg/apis/rbacreports/v1alpha1"
	"k8s-rbac-engine/pkg/conditions"
)

// samplesDir is the path to the built-in policies relative to this test
// file. The repo layout puts samples at the project root, so we walk up
// from pkg/apis/rbacreports/v1alpha1 four levels.
const samplesDir = "../../../../config/samples"

// TestBuiltInSamplesParse loads every YAML file in config/samples/ and
// asserts it unmarshals into a valid RbacPolicy with the required fields
// populated. This is the safety net for hand-written samples: if anyone
// adds a new policy with a typo'd severity, missing checkID, or wrong
// matchMode, this test fails before deploy.
//
// We exclude kustomization.yaml because it isn't an RbacPolicy.
func TestBuiltInSamplesParse(t *testing.T) {
	entries, err := os.ReadDir(samplesDir)
	if err != nil {
		t.Fatalf("read samples dir: %v", err)
	}

	policiesByCheckID := make(map[string][]string)
	var policyFiles int

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if name == "kustomization.yaml" {
			continue
		}
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}

		t.Run(name, func(t *testing.T) {
			path := filepath.Join(samplesDir, name)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}

			var p v1alpha1.RbacPolicy
			if err := yaml.UnmarshalStrict(data, &p); err != nil {
				t.Fatalf("unmarshal %s: %v", path, err)
			}

			validateSamplePolicy(t, name, &p)
			policiesByCheckID[p.Spec.CheckID] = append(policiesByCheckID[p.Spec.CheckID], name)
		})
		policyFiles++
	}

	if policyFiles != 14 {
		t.Errorf("expected exactly 14 sample policies, found %d", policyFiles)
	}

	// KSV048 has two files (core + apps) sharing one CheckID; the rest each get one.
	expected := map[string]int{
		"KSV041": 1, "KSV044": 1, "KSV045": 1, "KSV046": 1, "KSV047": 1,
		"KSV048": 2, "KSV049": 1, "KSV050": 1, "KSV053": 1, "KSV056": 1,
		"KSV112": 1, "KSV113": 1, "KSV114": 1,
	}
	for id, want := range expected {
		got := len(policiesByCheckID[id])
		if got != want {
			t.Errorf("CheckID %s: %d files, want %d (have: %v)", id, got, want, policiesByCheckID[id])
		}
	}
	for id := range policiesByCheckID {
		if _, ok := expected[id]; !ok {
			t.Errorf("unexpected CheckID %s in samples", id)
		}
	}
}

// validateSamplePolicy enforces the per-policy conventions for built-in samples.
func validateSamplePolicy(t *testing.T, name string, p *v1alpha1.RbacPolicy) {
	t.Helper()

	if p.Kind != "RbacPolicy" {
		t.Errorf("%s: kind = %q, want RbacPolicy", name, p.Kind)
	}
	if p.APIVersion != "rbacreports.in-cloud.io/v1alpha1" {
		t.Errorf("%s: apiVersion = %q, want rbacreports.in-cloud.io/v1alpha1", name, p.APIVersion)
	}
	if p.Name == "" {
		t.Errorf("%s: metadata.name is empty", name)
	}

	switch p.Spec.Severity {
	case v1alpha1.SeverityCritical, v1alpha1.SeverityHigh, v1alpha1.SeverityMedium, v1alpha1.SeverityLow:
		// ok
	default:
		t.Errorf("%s: invalid severity %q", name, p.Spec.Severity)
	}

	if p.Spec.CheckID == "" {
		t.Errorf("%s: checkID is empty", name)
	}
	if !strings.HasPrefix(p.Spec.CheckID, "KSV") {
		t.Errorf("%s: checkID %q does not start with KSV", name, p.Spec.CheckID)
	}
	if p.Spec.Title == "" {
		t.Errorf("%s: title is empty", name)
	}
	if p.Spec.Category == "" {
		t.Errorf("%s: category is empty", name)
	}
	if p.Spec.Description == "" {
		t.Errorf("%s: description is empty (every built-in policy must explain itself)", name)
	}
	if p.Spec.Remediation == "" {
		t.Errorf("%s: remediation is empty (every built-in policy must say how to fix)", name)
	}

	for _, k := range p.Spec.TargetKinds {
		if k != v1alpha1.KindRole && k != v1alpha1.KindClusterRole {
			t.Errorf("%s: invalid targetKind %q", name, k)
		}
	}

	if p.Spec.Match.MatchMode != "" &&
		p.Spec.Match.MatchMode != v1alpha1.MatchModeWildcard &&
		p.Spec.Match.MatchMode != v1alpha1.MatchModeExact {
		t.Errorf("%s: invalid matchMode %q", name, p.Spec.Match.MatchMode)
	}

	hasSimple := len(p.Spec.Match.Resources) > 0 && len(p.Spec.Match.Verbs) > 0
	hasConditions := len(p.Spec.Match.Conditions) > 0
	if !hasSimple && !hasConditions {
		t.Errorf("%s: neither simple match (resources+verbs) nor conditions; policy will never fire", name)
	}
	if hasSimple && hasConditions {
		t.Errorf("%s: both simple match and conditions present; conditions wins, drop the simple fields", name)
	}

	if hasConditions {
		validateConditions(t, name, p.Spec.Match.Conditions)
	}
}

func validateConditions(t *testing.T, name string, cs []conditions.Condition) {
	t.Helper()
	validFields := map[conditions.Field]bool{
		conditions.FieldVerbs:         true,
		conditions.FieldResources:     true,
		conditions.FieldAPIGroups:     true,
		conditions.FieldResourceNames: true,
	}
	validOps := map[conditions.Operator]bool{
		conditions.OpContainsExact:   true,
		conditions.OpContainsAny:     true,
		conditions.OpContainsAll:     true,
		conditions.OpNotContains:     true,
		conditions.OpHasIntersection: true,
	}
	for i, c := range cs {
		if !validFields[c.Field] {
			t.Errorf("%s: condition[%d] field %q is not one of verbs/resources/apiGroups/resourceNames", name, i, c.Field)
		}
		if !validOps[c.Operator] {
			t.Errorf("%s: condition[%d] operator %q is not a known operator", name, i, c.Operator)
		}
		// containsExact and notContains use Value; the rest use Values.
		switch c.Operator {
		case conditions.OpContainsExact, conditions.OpNotContains:
			if c.Value == "" {
				t.Errorf("%s: condition[%d] %s requires non-empty value", name, i, c.Operator)
			}
		case conditions.OpContainsAny, conditions.OpContainsAll, conditions.OpHasIntersection:
			if len(c.Values) == 0 {
				t.Errorf("%s: condition[%d] %s requires non-empty values", name, i, c.Operator)
			}
		}
	}
}
