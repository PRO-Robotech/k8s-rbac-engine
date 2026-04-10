package conditions

import (
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
)

func TestContainsExact(t *testing.T) {
	tests := []struct {
		name   string
		values []string
		target string
		want   bool
	}{
		{"verbs=[*]/target=*", []string{"*"}, "*", true},
		{"verbs=[get,*]/target=*", []string{"get", "*"}, "*", true},
		{"verbs=[get,list]/target=*", []string{"get", "list"}, "*", false},
		// Edge cases beyond the guide table.
		{"empty/target=*", []string{}, "*", false},
		{"nil/target=*", nil, "*", false},
		{"single-non-match", []string{"create"}, "delete", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ContainsExact(tt.values, tt.target); got != tt.want {
				t.Fatalf("ContainsExact(%v, %q) = %v, want %v", tt.values, tt.target, got, tt.want)
			}
		})
	}
}

func TestContainsAny(t *testing.T) {
	needles := []string{"create", "update", "delete", "*"}
	tests := []struct {
		name   string
		values []string
		want   bool
	}{
		{"verbs=[get,create]", []string{"get", "create"}, true}, // create is present
		{"verbs=[get,list]", []string{"get", "list"}, false},    // no overlap
		{"verbs=[*]", []string{"*"}, true},                      // literal "*" is present in needles
		// Edge cases.
		{"empty-values", []string{}, false},
		{"nil-values", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ContainsAny(tt.values, needles); got != tt.want {
				t.Fatalf("ContainsAny(%v, %v) = %v, want %v", tt.values, needles, got, tt.want)
			}
		})
	}

	t.Run("empty-needles", func(t *testing.T) {
		if got := ContainsAny([]string{"get"}, nil); got {
			t.Fatalf("ContainsAny with empty needles must be false")
		}
	})
}

func TestContainsAll(t *testing.T) {
	needles := []string{"pods", "pods/exec"}
	tests := []struct {
		name   string
		values []string
		want   bool
	}{
		{"resources=[pods,pods/exec,services]", []string{"pods", "pods/exec", "services"}, true},
		{"resources=[pods]", []string{"pods"}, false},           // missing pods/exec
		{"resources=[pods/exec]", []string{"pods/exec"}, false}, // missing pods
		// Edge cases.
		{"empty-values", []string{}, false},
		{"nil-values", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ContainsAll(tt.values, needles); got != tt.want {
				t.Fatalf("ContainsAll(%v, %v) = %v, want %v", tt.values, needles, got, tt.want)
			}
		})
	}

	t.Run("empty-needles-vacuous-true", func(t *testing.T) {
		if got := ContainsAll([]string{}, nil); !got {
			t.Fatalf("ContainsAll with empty needles must be true (vacuous truth)")
		}
	})
}

func TestNotContains(t *testing.T) {
	tests := []struct {
		name   string
		values []string
		target string
		want   bool
	}{
		{"resources=[pods,services]/target=*", []string{"pods", "services"}, "*", true},
		{"resources=[*]/target=*", []string{"*"}, "*", false},
		{"resources=[pods,*]/target=*", []string{"pods", "*"}, "*", false},
		// Edge cases.
		{"empty/target=*", []string{}, "*", true},  // missing token → not contained
		{"nil/target=anything", nil, "pods", true}, // missing token → not contained
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NotContains(tt.values, tt.target); got != tt.want {
				t.Fatalf("NotContains(%v, %q) = %v, want %v", tt.values, tt.target, got, tt.want)
			}
		})
	}
}

func TestHasIntersection(t *testing.T) {
	needles := []string{"create", "update", "delete"}
	tests := []struct {
		name   string
		values []string
		want   bool
	}{
		{"verbs=[get,create]", []string{"get", "create"}, true}, // literal overlap
		{"verbs=[*]", []string{"*"}, true},                      // wildcard on values side
		{"verbs=[get,list]", []string{"get", "list"}, false},    // no overlap
		// Edge cases beyond the guide table.
		{"empty-values", []string{}, false},
		{"nil-values", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := HasIntersection(tt.values, needles); got != tt.want {
				t.Fatalf("HasIntersection(%v, %v) = %v, want %v", tt.values, needles, got, tt.want)
			}
		})
	}

	t.Run("wildcard-on-needles-side", func(t *testing.T) {
		// "*" in needles also acts as wildcard — symmetry check.
		if got := HasIntersection([]string{"get"}, []string{"*"}); !got {
			t.Fatalf("HasIntersection: wildcard in needles must match any non-empty values")
		}
	})

	t.Run("wildcard-on-needles-side-empty-values", func(t *testing.T) {
		// Empty values still has no intersection — wildcard needs something to match.
		if got := HasIntersection(nil, []string{"*"}); got {
			t.Fatalf("HasIntersection: empty values must return false even with wildcard needles")
		}
	})

	t.Run("contrast-with-containsAny", func(t *testing.T) {
		// The guide explicitly contrasts hasIntersection vs containsAny:
		// hasIntersection treats "*" as wildcard, containsAny treats it as literal.
		values := []string{"*"}
		intNeedles := []string{"create"} // no literal "*" on needles side
		if !HasIntersection(values, intNeedles) {
			t.Fatalf("HasIntersection must return true when role has [*] (wildcard semantics)")
		}
		if ContainsAny(values, intNeedles) {
			t.Fatalf("ContainsAny must return false when needles has no literal '*' (literal semantics)")
		}
	})
}

// TestEvaluate verifies that multiple conditions are AND-joined.
func TestEvaluate(t *testing.T) {
	// wildcard verb on a concrete resource: containsExact verbs=* AND notContains resources=*
	wildcardVerbOnConcreteResource := []Condition{
		{Field: FieldVerbs, Operator: OpContainsExact, Value: "*"},
		{Field: FieldResources, Operator: OpNotContains, Value: "*"},
	}

	tests := []struct {
		name       string
		rule       rbacv1.PolicyRule
		conditions []Condition
		want       bool
	}{
		{
			name: "wildcard-verb-on-concrete-resource/match",
			rule: rbacv1.PolicyRule{
				Verbs:     []string{"*"},
				Resources: []string{"pods"},
			},
			conditions: wildcardVerbOnConcreteResource,
			want:       true,
		},
		{
			name: "wildcard-verb-on-concrete-resource/wildcard-in-resources-fails",
			rule: rbacv1.PolicyRule{
				Verbs:     []string{"*"},
				Resources: []string{"*"},
			},
			conditions: wildcardVerbOnConcreteResource,
			want:       false, // resources contains "*", notContains fails
		},
		{
			name: "wildcard-verb-on-concrete-resource/no-wildcard-verb-fails",
			rule: rbacv1.PolicyRule{
				Verbs:     []string{"get", "list"},
				Resources: []string{"pods"},
			},
			conditions: wildcardVerbOnConcreteResource,
			want:       false, // verbs has no literal "*", containsExact fails
		},
		{
			name:       "empty-conditions-vacuous-true",
			rule:       rbacv1.PolicyRule{Verbs: []string{"get"}},
			conditions: nil,
			want:       true,
		},
		{
			name: "unknown-operator-fails-closed",
			rule: rbacv1.PolicyRule{Verbs: []string{"*"}},
			conditions: []Condition{
				{Field: FieldVerbs, Operator: "containsAlmost", Value: "*"},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Evaluate(tt.rule, tt.conditions); got != tt.want {
				t.Fatalf("Evaluate() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestFieldValues confirms the rule-field extraction handles every valid
// field plus an unknown field (returns nil).
func TestFieldValues(t *testing.T) {
	rule := rbacv1.PolicyRule{
		Verbs:         []string{"get", "list"},
		Resources:     []string{"pods", "services"},
		APIGroups:     []string{""},
		ResourceNames: []string{"my-pod"},
	}

	tests := []struct {
		field Field
		want  []string
	}{
		{FieldVerbs, []string{"get", "list"}},
		{FieldResources, []string{"pods", "services"}},
		{FieldAPIGroups, []string{""}},
		{FieldResourceNames, []string{"my-pod"}},
		{Field("bogus"), nil},
	}
	for _, tt := range tests {
		t.Run(string(tt.field), func(t *testing.T) {
			got := FieldValues(rule, tt.field)
			if !equalSlices(got, tt.want) {
				t.Fatalf("FieldValues(%q) = %v, want %v", tt.field, got, tt.want)
			}
		})
	}
}

func equalSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}

	return true
}
