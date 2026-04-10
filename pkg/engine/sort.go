package engine

import (
	"sort"

	api "k8s-rbac-engine/pkg/apis/rbacgraph"
)

// sortByQuad sorts a slice by four string keys extracted via the key function.
func sortByQuad[T any](items []T, key func(*T) (string, string, string, string)) {
	sort.Slice(items, func(i, j int) bool {
		a1, a2, a3, a4 := key(&items[i])
		b1, b2, b3, b4 := key(&items[j])
		if a1 != b1 {
			return a1 < b1
		}
		if a2 != b2 {
			return a2 < b2
		}
		if a3 != b3 {
			return a3 < b3
		}

		return a4 < b4
	})
}

func sortNodes(nodes []api.GraphNode) {
	sortByQuad(nodes, func(n *api.GraphNode) (string, string, string, string) {
		return string(n.Type), n.Namespace, n.Name, n.ID
	})
}

func sortEdges(edges []api.GraphEdge) {
	sortByQuad(edges, func(e *api.GraphEdge) (string, string, string, string) {
		return string(e.Type), e.From, e.To, e.ID
	})
}
