package engine

import (
	"cmp"
	"fmt"
	"slices"

	rbacv1 "k8s.io/api/rbac/v1"

	api "k8s-rbac-engine/pkg/apis/rbacgraph"
)

func (c *subjectQueryContext) toGraphStatus() api.SubjectGraphReviewStatus {
	return api.SubjectGraphReviewStatus{
		Subject:          c.subject,
		ResolvedSubjects: cloneSubjectRefs(c.resolvedSubjects),
		MatchedRoles:     countNonNilRoles(c.roleHits),
		MatchedBindings:  countBindingAttrs(c.roleHits),
		Graph:            c.buildGraph(),
		Warnings:         cloneWarnings(c.warnings),
		KnownGaps:        c.snapshot.CloneKnownGaps(),
	}
}

func (c *subjectQueryContext) buildGraph() api.Graph {
	g := newGraphBuilder()

	subjectNID := subjectRefNodeID(c.subject)
	g.addNode(api.GraphNode{
		ID:        subjectNID,
		Type:      subjectNodeTypeFromKind(c.subject.Kind),
		Name:      c.subject.Name,
		Namespace: c.subject.Namespace,
	})

	for _, hit := range c.roleHits {
		roleNID := ""
		if hit.role != nil {
			roleNID = roleNodeID(hit.role)
			g.addNode(api.GraphNode{
				ID:              roleNID,
				Type:            roleType(hit.role),
				Name:            hit.role.Name,
				Namespace:       hit.role.Namespace,
				Labels:          hit.role.Labels,
				Annotations:     hit.role.Annotations,
				MatchedRuleRefs: append([]api.RuleRef(nil), hit.matchedRefs...),
				Assessment:      lookupAssessmentForRole(c.reportLookup, hit.role),
			})
		}

		for _, attr := range hit.bindingAttrs {
			c.emitBindingEdges(g, subjectNID, roleNID, attr, hit.matchedRefs)
		}
	}

	return g.graph()
}

func (c *subjectQueryContext) emitBindingEdges(
	g *graphBuilder, subjectNID, roleNID string,
	attr bindingAttr, matchedRefs []api.RuleRef,
) {
	bindingNID := bindingNodeID(attr.binding)
	g.addNode(api.GraphNode{
		ID:        bindingNID,
		Type:      bindingType(attr.binding),
		Name:      attr.binding.Name,
		Namespace: attr.binding.Namespace,
	})

	via := attr.viaSubject
	explain := "binding targets subject"
	if via != c.subject {
		explain = fmt.Sprintf("binding targets subject via %s %s", via.Kind, via.Name)
	}
	g.addEdge(api.GraphEdge{
		ID:      edgeIDFor(subjectNID, bindingNID, api.GraphEdgeTypeSubjects),
		From:    subjectNID,
		To:      bindingNID,
		Type:    api.GraphEdgeTypeSubjects,
		Explain: explain,
	})

	if roleNID == "" {
		return
	}
	g.addEdge(api.GraphEdge{
		ID:       edgeIDFor(bindingNID, roleNID, api.GraphEdgeTypeGrants),
		From:     bindingNID,
		To:       roleNID,
		Type:     api.GraphEdgeTypeGrants,
		RuleRefs: append([]api.RuleRef(nil), matchedRefs...),
		Explain:  edgeExplainGrants,
	})
}

type graphBuilder struct {
	nodes    []api.GraphNode
	edges    []api.GraphEdge
	nodeSeen map[string]struct{}
	edgeSeen map[string]struct{}
}

func newGraphBuilder() *graphBuilder {
	return &graphBuilder{
		nodeSeen: make(map[string]struct{}),
		edgeSeen: make(map[string]struct{}),
	}
}

func (g *graphBuilder) addNode(n api.GraphNode) {
	if _, ok := g.nodeSeen[n.ID]; ok {
		return
	}
	g.nodeSeen[n.ID] = struct{}{}
	g.nodes = append(g.nodes, n)
}

func (g *graphBuilder) addEdge(e api.GraphEdge) {
	if _, ok := g.edgeSeen[e.ID]; ok {
		return
	}
	g.edgeSeen[e.ID] = struct{}{}
	g.edges = append(g.edges, e)
}

func (g *graphBuilder) graph() api.Graph {
	slices.SortFunc(g.nodes, func(a, b api.GraphNode) int {
		return cmp.Compare(a.ID, b.ID)
	})
	slices.SortFunc(g.edges, func(a, b api.GraphEdge) int {
		return cmp.Compare(a.ID, b.ID)
	})

	return api.Graph{Nodes: g.nodes, Edges: g.edges}
}

// subjectRefNodeID is the SubjectRef counterpart of subjectNodeID in
// graph_nodes.go. It reuses the same prefix/shape for parity with forward
// queries so node IDs are stable across endpoints.
func subjectRefNodeID(ref api.SubjectRef) string {
	return subjectNodeID(rbacv1.Subject{
		Kind:      string(ref.Kind),
		Name:      ref.Name,
		Namespace: ref.Namespace,
	})
}

func subjectNodeTypeFromKind(kind api.SubjectKind) api.GraphNodeType {
	switch kind {
	case api.SubjectKindServiceAccount:
		return api.GraphNodeTypeServiceAccount
	case api.SubjectKindGroup:
		return api.GraphNodeTypeGroup
	default:
		return api.GraphNodeTypeUser
	}
}

func countNonNilRoles(hits []*roleHit) int {
	n := 0
	for _, hit := range hits {
		if hit.role != nil {
			n++
		}
	}

	return n
}

func countBindingAttrs(hits []*roleHit) int {
	n := 0
	for _, hit := range hits {
		n += len(hit.bindingAttrs)
	}

	return n
}
