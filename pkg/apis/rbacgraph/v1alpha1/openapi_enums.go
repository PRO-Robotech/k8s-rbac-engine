package v1alpha1

import (
	"k8s.io/kube-openapi/pkg/common"
	"k8s.io/kube-openapi/pkg/validation/spec"
)

// GetEnumOpenAPIDefinitions returns OpenAPI definitions with enum constraints
// for custom string types that openapi-gen does not handle automatically.
func GetEnumOpenAPIDefinitions(_ common.ReferenceCallback) map[string]common.OpenAPIDefinition {
	prefix := openAPIPrefix

	return map[string]common.OpenAPIDefinition{
		prefix + "MatchMode": {
			Schema: spec.Schema{
				SchemaProps: spec.SchemaProps{
					Description: "Match mode: 'any' (OR, default) or 'all' (AND).",
					Type:        []string{"string"},
					Enum:        []any{string(MatchModeAny), string(MatchModeAll)},
				},
			},
		},
		prefix + "PodPhaseMode": {
			Schema: spec.Schema{
				SchemaProps: spec.SchemaProps{
					Description: "Filter pods by phase: 'active' (Pending/Running/Unknown, default), 'running', or 'all'.",
					Type:        []string{"string"},
					Enum:        []any{string(PodPhaseModeActive), string(PodPhaseModeRunning), string(PodPhaseModeAll)},
				},
			},
		},
		prefix + "GraphNodeType": {
			Schema: spec.Schema{
				SchemaProps: spec.SchemaProps{
					Description: "Type of a node in the RBAC graph.",
					Type:        []string{"string"},
					Enum: []any{
						string(GraphNodeTypeRole), string(GraphNodeTypeClusterRole),
						string(GraphNodeTypeRoleBinding), string(GraphNodeTypeClusterRoleBinding),
						string(GraphNodeTypeUser), string(GraphNodeTypeGroup), string(GraphNodeTypeServiceAccount),
						string(GraphNodeTypePod), string(GraphNodeTypeWorkload),
						string(GraphNodeTypePodOverflow), string(GraphNodeTypeWorkloadOverflow),
					},
				},
			},
		},
		prefix + "GraphEdgeType": {
			Schema: spec.Schema{
				SchemaProps: spec.SchemaProps{
					Description: "Type of an edge in the RBAC graph.",
					Type:        []string{"string"},
					Enum: []any{
						string(GraphEdgeTypeAggregates), string(GraphEdgeTypeGrants),
						string(GraphEdgeTypeSubjects), string(GraphEdgeTypeRunsAs), string(GraphEdgeTypeOwnedBy),
					},
				},
			},
		},
		prefix + "WildcardMode": {
			Schema: spec.Schema{
				SchemaProps: spec.SchemaProps{
					Description: "Wildcard handling mode: 'wildcard' (`*` matches any value, default) or 'exact' (`*` is a literal string).",
					Type:        []string{"string"},
					Enum:        []any{string(WildcardModeWildcard), string(WildcardModeExact)},
				},
			},
		},
	}
}

// GetOpenAPIDefinitionsWithEnums returns the generated OpenAPI definitions
// merged with enum constraints for custom string types.
func GetOpenAPIDefinitionsWithEnums(ref common.ReferenceCallback) map[string]common.OpenAPIDefinition {
	defs := GetOpenAPIDefinitions(ref)
	enumDefs := GetEnumOpenAPIDefinitions(ref)
	for key := range enumDefs {
		defs[key] = enumDefs[key]
	}
	injectEnumsIntoStructFields(defs)

	return defs
}

// injectEnumsIntoStructFields patches struct field schemas in-place so that
// fields typed as MatchMode, PodPhaseMode, GraphNodeType, or GraphEdgeType
// carry enum constraints in the parent struct schema.
func injectEnumsIntoStructFields(defs map[string]common.OpenAPIDefinition) {
	prefix := openAPIPrefix

	patchField := func(typeName, fieldName string, enum []any) {
		def, ok := defs[prefix+typeName]
		if !ok || def.Schema.Properties == nil {
			return
		}
		prop, ok := def.Schema.Properties[fieldName]
		if !ok {
			return
		}
		prop.Enum = enum
		def.Schema.Properties[fieldName] = prop
		defs[prefix+typeName] = def
	}

	patchField("RoleGraphReviewSpec", "matchMode", []any{string(MatchModeAny), string(MatchModeAll)})
	patchField("RoleGraphReviewSpec", "podPhaseMode", []any{string(PodPhaseModeActive), string(PodPhaseModeRunning), string(PodPhaseModeAll)})
	patchField("RoleGraphReviewSpec", "wildcardMode", []any{string(WildcardModeWildcard), string(WildcardModeExact)})
	patchField("RolePermissionsViewSpec", "matchMode", []any{string(MatchModeAny), string(MatchModeAll)})
	patchField("RolePermissionsViewSpec", "wildcardMode", []any{string(WildcardModeWildcard), string(WildcardModeExact)})
	patchField("GraphNode", "type", []any{
		string(GraphNodeTypeRole), string(GraphNodeTypeClusterRole),
		string(GraphNodeTypeRoleBinding), string(GraphNodeTypeClusterRoleBinding),
		string(GraphNodeTypeUser), string(GraphNodeTypeGroup), string(GraphNodeTypeServiceAccount),
		string(GraphNodeTypePod), string(GraphNodeTypeWorkload),
		string(GraphNodeTypePodOverflow), string(GraphNodeTypeWorkloadOverflow),
	})
	patchField("GraphEdge", "type", []any{
		string(GraphEdgeTypeAggregates), string(GraphEdgeTypeGrants),
		string(GraphEdgeTypeSubjects), string(GraphEdgeTypeRunsAs), string(GraphEdgeTypeOwnedBy),
	})
}
