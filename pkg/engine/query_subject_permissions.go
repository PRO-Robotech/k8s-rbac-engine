package engine

import (
	"cmp"
	"slices"

	api "k8s-rbac-engine/pkg/apis/rbacgraph"
)

func (c *subjectQueryContext) toPermissionsStatus() api.SubjectPermissionsViewStatus {
	return api.SubjectPermissionsViewStatus{
		Subject:          c.subject,
		ResolvedSubjects: cloneSubjectRefs(c.resolvedSubjects),
		APIGroups:        c.buildAPIGroupsAggregated(),
		NonResourceURLs:  c.buildNonResourceURLsAggregated(),
		Grants:           c.buildAttributedGrants(),
		Bindings:         c.buildSubjectBindings(),
		Roles:            c.buildRoleSummaries(),
		Warnings:         cloneWarnings(c.warnings),
	}
}

type resourceKey struct {
	apiGroup string
	resource string
}

// buildAPIGroupsAggregated produces the forward-compatible permission tree
// — apiGroup → resource → verb → granted. Rules[] is intentionally empty
// in the reverse projection: full provenance lives in Status.Grants.
func (c *subjectQueryContext) buildAPIGroupsAggregated() []api.APIGroupPermissions {
	granted := make(map[resourceKey]map[string]struct{})

	for _, hit := range c.roleHits {
		if hit.role == nil {
			continue
		}
		for i := range hit.matchedRefs {
			ref := &hit.matchedRefs[i]
			if len(ref.NonResourceURLs) > 0 {
				continue
			}
			if ref.Verb == "" || ref.Resource == "" {
				continue
			}
			key := resourceKey{apiGroup: ref.APIGroup, resource: ref.Resource}
			if granted[key] == nil {
				granted[key] = make(map[string]struct{})
			}
			granted[key][ref.Verb] = struct{}{}
		}
	}
	if len(granted) == 0 {
		return []api.APIGroupPermissions{}
	}

	groupMap := make(map[string][]api.ResourcePermissions)
	for key, verbs := range granted {
		verbPerms := make(map[string]api.VerbPermission, len(verbs))
		for v := range verbs {
			verbPerms[v] = api.VerbPermission{Granted: true, SupportedByAPI: true}
		}
		groupMap[key.apiGroup] = append(groupMap[key.apiGroup], api.ResourcePermissions{
			Plural: key.resource,
			Verbs:  verbPerms,
		})
	}

	groups := make([]api.APIGroupPermissions, 0, len(groupMap))
	for apiGroup, resources := range groupMap {
		slices.SortFunc(resources, func(a, b api.ResourcePermissions) int {
			return cmp.Compare(a.Plural, b.Plural)
		})
		groups = append(groups, api.APIGroupPermissions{
			APIGroup:       apiGroup,
			ResourcesCount: len(resources),
			Resources:      resources,
		})
	}
	slices.SortFunc(groups, func(a, b api.APIGroupPermissions) int {
		return cmp.Compare(a.APIGroup, b.APIGroup)
	})

	return groups
}

func (c *subjectQueryContext) buildNonResourceURLsAggregated() *api.NonResourceURLPermissions {
	granted := c.collectNonResourceURLGrants()
	if len(granted) == 0 {
		return nil
	}
	urls := make([]api.NonResourceURLPermissionEntry, 0, len(granted))
	for url, verbs := range granted {
		verbPerms := make(map[string]api.VerbPermission, len(verbs))
		for v := range verbs {
			verbPerms[v] = api.VerbPermission{Granted: true, SupportedByAPI: true}
		}
		urls = append(urls, api.NonResourceURLPermissionEntry{URL: url, Verbs: verbPerms})
	}
	slices.SortFunc(urls, func(a, b api.NonResourceURLPermissionEntry) int {
		return cmp.Compare(a.URL, b.URL)
	})

	return &api.NonResourceURLPermissions{URLsCount: len(urls), URLs: urls}
}

func (c *subjectQueryContext) collectNonResourceURLGrants() map[string]map[string]struct{} {
	granted := make(map[string]map[string]struct{})
	for _, hit := range c.roleHits {
		if hit.role == nil {
			continue
		}
		for i := range hit.matchedRefs {
			ref := &hit.matchedRefs[i]
			if len(ref.NonResourceURLs) == 0 {
				continue
			}
			for _, url := range ref.NonResourceURLs {
				if granted[url] == nil {
					granted[url] = make(map[string]struct{})
				}
				if ref.Verb != "" {
					granted[url][ref.Verb] = struct{}{}
				}
			}
		}
	}

	return granted
}

func (c *subjectQueryContext) buildAttributedGrants() []api.AttributedGrant {
	grants := make([]api.AttributedGrant, 0)
	for _, hit := range c.roleHits {
		if hit.role == nil {
			continue
		}
		source := roleRefFromRecord(hit.role)
		for _, attr := range hit.bindingAttrs {
			if attr.broken {
				continue
			}
			bindingSource := bindingRefFromRecord(attr.binding)
			for i := range hit.matchedRefs {
				grants = append(grants, attributedGrantFromRef(&hit.matchedRefs[i], source, bindingSource))
			}
		}
	}
	slices.SortFunc(grants, compareAttributedGrant)

	return grants
}

func attributedGrantFromRef(ref *api.RuleRef, role api.RoleRef, binding api.BindingRef) api.AttributedGrant {
	g := api.AttributedGrant{
		SourceRole:    role,
		SourceBinding: binding,
		APIGroup:      ref.APIGroup,
		Resource:      ref.Resource,
		Verb:          ref.Verb,
	}
	if len(ref.ResourceNames) > 0 {
		g.ResourceNames = append([]string(nil), ref.ResourceNames...)
	}
	if len(ref.NonResourceURLs) > 0 {
		g.NonResourceURL = ref.NonResourceURLs[0]
	}

	return g
}

func compareAttributedGrant(a, b api.AttributedGrant) int {
	if d := cmp.Compare(a.SourceRole.Kind, b.SourceRole.Kind); d != 0 {
		return d
	}
	if d := cmp.Compare(a.SourceRole.Namespace, b.SourceRole.Namespace); d != 0 {
		return d
	}
	if d := cmp.Compare(a.SourceRole.Name, b.SourceRole.Name); d != 0 {
		return d
	}
	if d := cmp.Compare(a.SourceBinding.Namespace, b.SourceBinding.Namespace); d != 0 {
		return d
	}
	if d := cmp.Compare(a.SourceBinding.Name, b.SourceBinding.Name); d != 0 {
		return d
	}
	if d := cmp.Compare(a.APIGroup, b.APIGroup); d != 0 {
		return d
	}
	if d := cmp.Compare(a.Resource, b.Resource); d != 0 {
		return d
	}
	if d := cmp.Compare(a.NonResourceURL, b.NonResourceURL); d != 0 {
		return d
	}

	return cmp.Compare(a.Verb, b.Verb)
}

func (c *subjectQueryContext) buildSubjectBindings() []api.SubjectBinding {
	bindings := make([]api.SubjectBinding, 0)
	for _, hit := range c.roleHits {
		for _, attr := range hit.bindingAttrs {
			bindings = append(bindings, api.SubjectBinding{
				Kind:           api.BindingKind(attr.binding.Kind),
				Name:           attr.binding.Name,
				Namespace:      attr.binding.Namespace,
				RoleRef:        roleRefFromKey(attr.binding.RoleRef),
				EffectiveScope: attr.scope,
				ViaSubject:     attr.viaSubject,
				Broken:         attr.broken,
			})
		}
	}
	slices.SortFunc(bindings, compareSubjectBinding)

	return bindings
}

func compareSubjectBinding(a, b api.SubjectBinding) int {
	if d := cmp.Compare(a.Namespace, b.Namespace); d != 0 {
		return d
	}
	if d := cmp.Compare(string(a.Kind), string(b.Kind)); d != 0 {
		return d
	}

	return cmp.Compare(a.Name, b.Name)
}

func (c *subjectQueryContext) buildRoleSummaries() []api.SubjectRoleSummary {
	roles := make([]api.SubjectRoleSummary, 0, len(c.roleHits))
	for _, hit := range c.roleHits {
		summary := api.SubjectRoleSummary{Ref: roleRefFromKey(hit.refKey)}
		switch {
		case hit.role == nil:
			summary.Phantom = true
		case len(hit.role.Rules) == 0:
			summary.Phantom = true
			summary.Assessment = lookupAssessmentForRole(c.reportLookup, hit.role)
		default:
			summary.Assessment = lookupAssessmentForRole(c.reportLookup, hit.role)
		}
		roles = append(roles, summary)
	}
	slices.SortFunc(roles, func(a, b api.SubjectRoleSummary) int {
		if d := cmp.Compare(string(a.Ref.Kind), string(b.Ref.Kind)); d != 0 {
			return d
		}
		if d := cmp.Compare(a.Ref.Namespace, b.Ref.Namespace); d != 0 {
			return d
		}

		return cmp.Compare(a.Ref.Name, b.Ref.Name)
	})

	return roles
}

func cloneSubjectRefs(refs []api.SubjectRef) []api.SubjectRef {
	if len(refs) == 0 {
		return nil
	}
	out := make([]api.SubjectRef, len(refs))
	copy(out, refs)

	return out
}

func cloneWarnings(ws []api.SubjectWarning) []api.SubjectWarning {
	if len(ws) == 0 {
		return nil
	}
	out := make([]api.SubjectWarning, len(ws))
	copy(out, ws)

	return out
}
