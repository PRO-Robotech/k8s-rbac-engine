package v1alpha1

import (
	"reflect"
	"testing"
	"unsafe"

	rbacgraph "k8s-rbac-engine/pkg/apis/rbacgraph"
)

// TestConversionLayoutCompatibility asserts byte-identical layout between
// v1alpha1 and rbacgraph types for every struct converted via an unsafe
// pointer cast in zz_generated.conversion.go. Add new layout-sensitive
// types to the table as they appear in the generated conversion code.
func TestConversionLayoutCompatibility(t *testing.T) {
	cases := []struct {
		name string
		v1   any
		hub  any
	}{
		{"Assessment", Assessment{}, rbacgraph.Assessment{}},
		{"APIGroupPermissions", APIGroupPermissions{}, rbacgraph.APIGroupPermissions{}},
		{"GraphNode", GraphNode{}, rbacgraph.GraphNode{}},
		{"GraphEdge", GraphEdge{}, rbacgraph.GraphEdge{}},
		{"NonResourceURLEntry", NonResourceURLEntry{}, rbacgraph.NonResourceURLEntry{}},
		{"NonResourceURLPermissionEntry", NonResourceURLPermissionEntry{}, rbacgraph.NonResourceURLPermissionEntry{}},
		{"NonResourceURLPermissions", NonResourceURLPermissions{}, rbacgraph.NonResourceURLPermissions{}},
		{"ResourceMapRow", ResourceMapRow{}, rbacgraph.ResourceMapRow{}},
		{"ResourcePermissions", ResourcePermissions{}, rbacgraph.ResourcePermissions{}},
		{"RuleRef", RuleRef{}, rbacgraph.RuleRef{}},
		{"GrantingRule", GrantingRule{}, rbacgraph.GrantingRule{}},
		{"VerbPermission", VerbPermission{}, rbacgraph.VerbPermission{}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertLayoutCompatible(t, tc.v1, tc.hub)
		})
	}
}

// assertLayoutCompatible verifies two struct values share identical size,
// field count, and per-field name/offset/size.
func assertLayoutCompatible(t *testing.T, v1, hub any) {
	t.Helper()
	v1T := reflect.TypeOf(v1)
	hubT := reflect.TypeOf(hub)

	if got, want := v1T.Size(), hubT.Size(); got != want {
		t.Fatalf("size mismatch: v1alpha1=%d, hub=%d", got, want)
	}
	if got, want := v1T.NumField(), hubT.NumField(); got != want {
		t.Fatalf("field count mismatch: v1alpha1=%d, hub=%d", got, want)
	}
	for i := range v1T.NumField() {
		v1f := v1T.Field(i)
		hubf := hubT.Field(i)
		if v1f.Name != hubf.Name {
			t.Errorf("field[%d] name: v1alpha1=%q, hub=%q", i, v1f.Name, hubf.Name)
		}
		if v1f.Offset != hubf.Offset {
			t.Errorf("field[%d] %q offset: v1alpha1=%d, hub=%d",
				i, v1f.Name, v1f.Offset, hubf.Offset)
		}
		if v1f.Type.Size() != hubf.Type.Size() {
			t.Errorf("field[%d] %q size: v1alpha1=%d, hub=%d",
				i, v1f.Name, v1f.Type.Size(), hubf.Type.Size())
		}
	}
}

// Keep the unsafe import alive so goimports doesn't strip it.
var _ = unsafe.Sizeof(GraphNode{})
