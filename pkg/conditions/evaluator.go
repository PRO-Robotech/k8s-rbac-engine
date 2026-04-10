// Package conditions implements the RbacPolicy advanced-match DSL: a set of
// predicates evaluated against a single PolicyRule. All conditions in a
// policy are AND-joined. Only hasIntersection treats "*" as a wildcard;
// every other operator compares literally.
package conditions

import (
	"slices"

	rbacv1 "k8s.io/api/rbac/v1"
)

// Field identifies which slice of a PolicyRule a condition targets.
type Field string

const (
	FieldVerbs         Field = "verbs"
	FieldResources     Field = "resources"
	FieldAPIGroups     Field = "apiGroups"
	FieldResourceNames Field = "resourceNames"
)

// Operator identifies the predicate kind.
type Operator string

const (
	OpContainsExact   Operator = "containsExact"
	OpContainsAny     Operator = "containsAny"
	OpContainsAll     Operator = "containsAll"
	OpNotContains     Operator = "notContains"
	OpHasIntersection Operator = "hasIntersection"
)

// Condition is one predicate of an RbacPolicy advanced-match block.
// containsExact and notContains read Value; containsAny, containsAll, and
// hasIntersection read Values.
type Condition struct {
	Field    Field    `json:"field"`
	Operator Operator `json:"operator"`
	Value    string   `json:"value,omitempty"`
	Values   []string `json:"values,omitempty"`
}

// Evaluate returns true when every condition holds for the given PolicyRule.
// An empty slice returns true.
func Evaluate(rule rbacv1.PolicyRule, conditions []Condition) bool {
	for _, c := range conditions {
		if !evaluateOne(rule, c) {
			return false
		}
	}

	return true
}

func evaluateOne(rule rbacv1.PolicyRule, c Condition) bool {
	values := FieldValues(rule, c.Field)
	switch c.Operator {
	case OpContainsExact:
		return ContainsExact(values, c.Value)
	case OpContainsAny:
		return ContainsAny(values, c.Values)
	case OpContainsAll:
		return ContainsAll(values, c.Values)
	case OpNotContains:
		return NotContains(values, c.Value)
	case OpHasIntersection:
		return HasIntersection(values, c.Values)
	}

	return false
}

// FieldValues returns the slice of rule corresponding to f. Unknown fields
// return nil so that operators see an empty slice (no values → most operators
// return false naturally).
func FieldValues(rule rbacv1.PolicyRule, f Field) []string {
	switch f {
	case FieldVerbs:
		return rule.Verbs
	case FieldResources:
		return rule.Resources
	case FieldAPIGroups:
		return rule.APIGroups
	case FieldResourceNames:
		return rule.ResourceNames
	}

	return nil
}

// ContainsExact reports whether values contains target as a literal element.
// "*" is compared literally — pass "*" to find rules with a wildcard token.
func ContainsExact(values []string, target string) bool {
	return slices.Contains(values, target)
}

// ContainsAny reports whether values contains at least one element from
// needles. All comparisons are literal; "*" has no special meaning.
func ContainsAny(values, needles []string) bool {
	if len(values) == 0 || len(needles) == 0 {
		return false
	}
	set := make(map[string]struct{}, len(values))
	for _, v := range values {
		set[v] = struct{}{}
	}
	for _, n := range needles {
		if _, ok := set[n]; ok {
			return true
		}
	}

	return false
}

// ContainsAll reports whether values contains every element of needles.
// All comparisons are literal. An empty needles slice returns true.
func ContainsAll(values, needles []string) bool {
	if len(needles) == 0 {
		return true
	}
	set := make(map[string]struct{}, len(values))
	for _, v := range values {
		set[v] = struct{}{}
	}
	for _, n := range needles {
		if _, ok := set[n]; !ok {
			return false
		}
	}

	return true
}

// NotContains reports whether values does NOT contain target as a literal
// element. It is the strict negation of ContainsExact.
func NotContains(values []string, target string) bool {
	return !ContainsExact(values, target)
}

// HasIntersection reports whether values intersects needles, treating "*" on
// either side as a wildcard that matches any element of the other slice.
//
// This is the only operator where "*" is wildcard-aware. Empty inputs return
// false: an empty set has no intersection with anything.
func HasIntersection(values, needles []string) bool {
	if len(values) == 0 || len(needles) == 0 {
		return false
	}
	if slices.Contains(values, "*") || slices.Contains(needles, "*") {
		return true
	}
	set := make(map[string]struct{}, len(values))
	for _, v := range values {
		set[v] = struct{}{}
	}
	for _, n := range needles {
		if _, ok := set[n]; ok {
			return true
		}
	}

	return false
}
