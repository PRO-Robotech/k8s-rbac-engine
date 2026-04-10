package engine

import (
	"sort"
	"strings"

	api "k8s-rbac-engine/pkg/apis/rbacgraph"
	"k8s-rbac-engine/pkg/indexer"
)

type resourceAccumulator struct {
	APIGroup string
	Resource string
	Verb     string
	roles    map[indexer.RoleID]struct{}
	bindings map[string]struct{}
	subjects map[string]struct{}
}

type resourceRowKey struct {
	apiGroup          string
	resource          string
	subresource       string
	verb              string
	nonResourceJoined string
}

func (qc *queryContext) accumulateResourceRows(refs []api.RuleRef, roleID indexer.RoleID, bindingID, subjectID string) {
	accumulateResourceRowsInto(qc.resourceRows, refs, roleID, bindingID, subjectID)
}

func accumulateResourceRowsInto(rows map[resourceRowKey]*resourceAccumulator, refs []api.RuleRef, roleID indexer.RoleID, bindingID, subjectID string) {
	for i := range refs {
		ref := &refs[i]
		key := resourceRowKey{
			apiGroup:    ref.APIGroup,
			resource:    ref.Resource,
			subresource: ref.Subresource,
			verb:        ref.Verb,
		}
		if len(ref.NonResourceURLs) > 0 {
			key.nonResourceJoined = strings.Join(ref.NonResourceURLs, ",")
		}
		acc, ok := rows[key]
		if !ok {
			resource := ref.Resource
			if ref.Subresource != "" {
				resource = ref.Resource + "/" + ref.Subresource
			}
			if len(ref.NonResourceURLs) > 0 {
				resource = strings.Join(ref.NonResourceURLs, ",")
			}
			acc = &resourceAccumulator{
				APIGroup: ref.APIGroup,
				Resource: resource,
				Verb:     ref.Verb,
				roles:    make(map[indexer.RoleID]struct{}),
				bindings: make(map[string]struct{}),
				subjects: make(map[string]struct{}),
			}
			rows[key] = acc
		}
		if roleID != "" {
			acc.roles[roleID] = struct{}{}
		}
		if bindingID != "" {
			acc.bindings[bindingID] = struct{}{}
		}
		if subjectID != "" {
			acc.subjects[subjectID] = struct{}{}
		}
	}
}

func collapseResourceRows(rows map[resourceRowKey]*resourceAccumulator) []api.ResourceMapRow {
	out := make([]api.ResourceMapRow, 0, len(rows))
	for _, row := range rows {
		out = append(out, api.ResourceMapRow{
			APIGroup:     row.APIGroup,
			Resource:     row.Resource,
			Verb:         row.Verb,
			RoleCount:    len(row.roles),
			BindingCount: len(row.bindings),
			SubjectCount: len(row.subjects),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].APIGroup != out[j].APIGroup {
			return out[i].APIGroup < out[j].APIGroup
		}
		if out[i].Resource != out[j].Resource {
			return out[i].Resource < out[j].Resource
		}

		return out[i].Verb < out[j].Verb
	})

	return out
}
