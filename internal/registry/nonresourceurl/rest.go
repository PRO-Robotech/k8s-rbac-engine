package nonresourceurl

import (
	"cmp"
	"context"
	"slices"
	"strings"

	metainternalversion "k8s.io/apimachinery/pkg/apis/meta/internalversion"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/registry/rest"

	"k8s-rbac-engine/pkg/apis/rbacgraph"
	"k8s-rbac-engine/pkg/indexer"
)

type REST struct {
	indexer *indexer.Indexer
}

var _ rest.Storage = &REST{}
var _ rest.Lister = &REST{}
var _ rest.SingularNameProvider = &REST{}

func NewREST(idx *indexer.Indexer) *REST {
	return &REST{indexer: idx}
}

func (r *REST) New() runtime.Object {
	return &rbacgraph.NonResourceURLList{}
}

func (r *REST) NewList() runtime.Object {
	return &rbacgraph.NonResourceURLList{}
}

func (r *REST) Destroy() {}

func (r *REST) NamespaceScoped() bool {
	return false
}

func (r *REST) GetSingularName() string {
	return "nonresourceurl"
}

func (r *REST) ConvertToTable(_ context.Context, obj, _ runtime.Object) (*metav1.Table, error) {
	list, ok := obj.(*rbacgraph.NonResourceURLList)
	if !ok {
		return &metav1.Table{}, nil
	}
	table := &metav1.Table{
		ColumnDefinitions: []metav1.TableColumnDefinition{
			{Name: "URL", Type: "string"},
			{Name: "Verbs", Type: "string"},
			{Name: "Roles", Type: "integer"},
		},
	}
	for _, entry := range list.Items {
		table.Rows = append(table.Rows, metav1.TableRow{
			Cells: []any{entry.URL, joinStrings(entry.Verbs), len(entry.Roles)},
		})
	}

	return table, nil
}

func (r *REST) List(_ context.Context, _ *metainternalversion.ListOptions) (runtime.Object, error) {
	snapshot := r.indexer.Snapshot()

	type urlInfo struct {
		verbs map[string]struct{}
		roles map[string]struct{}
	}

	index := make(map[string]*urlInfo)

	for _, role := range snapshot.RolesByID {
		for _, rule := range role.Rules {
			if len(rule.NonResourceURLs) == 0 {
				continue
			}
			for _, url := range rule.NonResourceURLs {
				info, ok := index[url]
				if !ok {
					info = &urlInfo{
						verbs: make(map[string]struct{}),
						roles: make(map[string]struct{}),
					}
					index[url] = info
				}
				for _, verb := range rule.Verbs {
					info.verbs[verb] = struct{}{}
				}
				info.roles[role.Name] = struct{}{}
			}
		}
	}

	items := make([]rbacgraph.NonResourceURLEntry, 0, len(index))
	for url, info := range index {
		verbs := sortedKeys(info.verbs)
		roles := sortedKeys(info.roles)
		items = append(items, rbacgraph.NonResourceURLEntry{
			URL:   url,
			Verbs: verbs,
			Roles: roles,
		})
	}
	slices.SortFunc(items, func(a, b rbacgraph.NonResourceURLEntry) int {
		return cmp.Compare(a.URL, b.URL)
	})

	return &rbacgraph.NonResourceURLList{Items: items}, nil
}

func sortedKeys(m map[string]struct{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)

	return keys
}

func joinStrings(strs []string) string {
	return strings.Join(strs, ", ")
}
