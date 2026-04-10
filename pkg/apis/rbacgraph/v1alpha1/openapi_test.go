package v1alpha1

import (
	"encoding/json"
	"strings"
	"testing"

	"k8s.io/kube-openapi/pkg/builder"
	"k8s.io/kube-openapi/pkg/common"
	"k8s.io/kube-openapi/pkg/validation/spec"
)

// TestOpenAPIRefsResolvable builds the OpenAPI spec from our generated
// definitions and checks that every $ref pointer resolves to an existing
// definition.
func TestOpenAPIRefsResolvable(t *testing.T) {
	config := &common.Config{
		Info: &spec.Info{
			InfoProps: spec.InfoProps{Title: "test", Version: "v0"},
		},
		GetDefinitions: GetOpenAPIDefinitionsWithEnums,
	}

	names := []string{
		RoleGraphReview{}.OpenAPIModelName(),
		RoleGraphReviewSpec{}.OpenAPIModelName(),
		RoleGraphReviewStatus{}.OpenAPIModelName(),
		Selector{}.OpenAPIModelName(),
		NamespaceScope{}.OpenAPIModelName(),
		Graph{}.OpenAPIModelName(),
		GraphNode{}.OpenAPIModelName(),
		GraphEdge{}.OpenAPIModelName(),
		Assessment{}.OpenAPIModelName(),
		RuleRef{}.OpenAPIModelName(),
		ResourceMapRow{}.OpenAPIModelName(),
		RolePermissionsView{}.OpenAPIModelName(),
		RolePermissionsViewSpec{}.OpenAPIModelName(),
		RolePermissionsViewStatus{}.OpenAPIModelName(),
	}

	swagger, err := builder.BuildOpenAPIDefinitionsForResources(config, names...)
	if err != nil {
		t.Fatalf("BuildOpenAPIDefinitionsForResources: %v", err)
	}

	// Serialize to JSON and back to a generic map so we can walk all $ref
	// values without importing every OpenAPI struct.
	raw, err := json.Marshal(swagger)
	if err != nil {
		t.Fatalf("marshal swagger: %v", err)
	}

	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal swagger: %v", err)
	}

	defs, ok := doc["definitions"].(map[string]any)
	if !ok || len(defs) == 0 {
		t.Fatal("spec contains no definitions")
	}

	// Collect every $ref target from the whole document.
	var refs []string
	collectRefs(doc, &refs)

	for _, ref := range refs {
		// Only validate local definition refs (#/definitions/...).
		if !strings.HasPrefix(ref, "#/definitions/") {
			continue
		}
		name := strings.TrimPrefix(ref, "#/definitions/")
		if _, exists := defs[name]; !exists {
			t.Errorf("unresolved $ref %q: definition %q not found in spec", ref, name)
		}
	}
}

// collectRefs recursively walks a JSON-decoded structure and appends every
// value found under a "$ref" key.
func collectRefs(v any, out *[]string) {
	switch val := v.(type) {
	case map[string]any:
		if ref, ok := val["$ref"].(string); ok {
			*out = append(*out, ref)
		}
		for _, child := range val {
			collectRefs(child, out)
		}
	case []any:
		for _, item := range val {
			collectRefs(item, out)
		}
	}
}
