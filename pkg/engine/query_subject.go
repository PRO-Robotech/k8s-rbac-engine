package engine

import (
	"fmt"
	"slices"
	"strings"

	api "k8s-rbac-engine/pkg/apis/rbacgraph"
	"k8s-rbac-engine/pkg/indexer"
	"k8s-rbac-engine/pkg/matcher"
)

const (
	subjectLargeResponseThreshold = 100
	groupSystemAuthenticated      = "system:authenticated"
	groupAllServiceAccounts       = "system:serviceaccounts"
	groupServiceAccountsPrefix    = "system:serviceaccounts:"
	impersonateVerb               = "impersonate"
)

// subjectQueryContext is the shared state for reverse-graph traversals. Both
// SubjectPermissionsView and SubjectGraphReview projections read from it
// after expand()+collect() populate the role/binding hits.
type subjectQueryContext struct {
	snapshot      *indexer.Snapshot
	discovery     *indexer.APIDiscoveryCache
	reportLookup  ReportLookup
	subject       api.SubjectRef
	selector      api.Selector
	matchMode     api.MatchMode
	wildcardMode  api.WildcardMode
	directOnly    bool
	filterPhantom bool

	resolvedSubjects []api.SubjectRef
	resolvedKeys     []indexer.SubjectKey

	roleHits    []*roleHit
	roleHitByID map[indexer.RoleID]*roleHit
	warnings    []api.SubjectWarning
	warningSeen map[string]struct{}
}

// roleHit captures one role reached from the subject (possibly via multiple
// bindings or identities). role is nil if every binding that referenced
// this RoleRef was broken (role deleted).
type roleHit struct {
	role         *indexer.RoleRecord
	refKey       indexer.RoleRefKey
	bindingAttrs []bindingAttr
	matchedRefs  []api.RuleRef
}

// bindingAttr describes one binding that targets a subject identity.
type bindingAttr struct {
	binding    *indexer.BindingRecord
	viaSubject api.SubjectRef
	scope      api.EffectiveScope
	broken     bool
}

// QuerySubjectPermissions builds a SubjectPermissionsView status by expanding
// the subject's identity set, looking up all bindings targeting any expanded
// identity, and aggregating the matched permissions across every bound role.
func (e *Engine) QuerySubjectPermissions(
	snapshot *indexer.Snapshot,
	spec api.SubjectPermissionsViewSpec,
	discovery *indexer.APIDiscoveryCache,
) api.SubjectPermissionsViewStatus {
	normalized := spec
	normalized.EnsureDefaults()

	ctx := newSubjectQueryContext(snapshot, discovery, e.ReportLookup,
		normalized.Subject, normalized.Selector,
		normalized.MatchMode, normalized.WildcardMode,
		normalized.DirectOnly, normalized.FilterPhantomAPIs)
	ctx.expand()
	ctx.collect()
	ctx.emitWarnings()

	return ctx.toPermissionsStatus()
}

// QuerySubjectGraph builds a SubjectGraphReview status using the same
// underlying traversal as QuerySubjectPermissions but projects the result
// as a nodes+edges graph.
func (e *Engine) QuerySubjectGraph(
	snapshot *indexer.Snapshot,
	spec api.SubjectGraphReviewSpec,
	discovery *indexer.APIDiscoveryCache,
) api.SubjectGraphReviewStatus {
	normalized := spec
	normalized.EnsureDefaults()

	ctx := newSubjectQueryContext(snapshot, discovery, e.ReportLookup,
		normalized.Subject, normalized.Selector,
		normalized.MatchMode, normalized.WildcardMode,
		normalized.DirectOnly, normalized.FilterPhantomAPIs)
	ctx.expand()
	ctx.collect()
	ctx.emitWarnings()

	return ctx.toGraphStatus()
}

func newSubjectQueryContext(
	snapshot *indexer.Snapshot,
	discovery *indexer.APIDiscoveryCache,
	reportLookup ReportLookup,
	subject api.SubjectRef,
	selector api.Selector,
	matchMode api.MatchMode,
	wildcardMode api.WildcardMode,
	directOnly, filterPhantom bool,
) *subjectQueryContext {
	return &subjectQueryContext{
		snapshot:      snapshot,
		discovery:     discovery,
		reportLookup:  reportLookup,
		subject:       subject,
		selector:      selector,
		matchMode:     matchMode,
		wildcardMode:  wildcardMode,
		directOnly:    directOnly,
		filterPhantom: filterPhantom,
		roleHitByID:   make(map[indexer.RoleID]*roleHit),
		warningSeen:   make(map[string]struct{}),
	}
}

// expand fills resolvedSubjects and resolvedKeys with the subject's own
// identity plus any implicit k8s groups it belongs to. Groups never expand
// further; DirectOnly skips expansion entirely.
func (c *subjectQueryContext) expand() {
	primary := c.subject
	c.resolvedSubjects = append(c.resolvedSubjects, primary)
	c.resolvedKeys = append(c.resolvedKeys, subjectKeyFromRef(primary))

	if c.directOnly {
		return
	}

	switch primary.Kind {
	case api.SubjectKindServiceAccount:
		c.appendResolved(api.SubjectRef{Kind: api.SubjectKindGroup, Name: groupServiceAccountsPrefix + primary.Namespace})
		c.appendResolved(api.SubjectRef{Kind: api.SubjectKindGroup, Name: groupAllServiceAccounts})
		c.appendResolved(api.SubjectRef{Kind: api.SubjectKindGroup, Name: groupSystemAuthenticated})
	case api.SubjectKindUser:
		c.appendResolved(api.SubjectRef{Kind: api.SubjectKindGroup, Name: groupSystemAuthenticated})
	case api.SubjectKindGroup:
		// Groups do not expand — "what can group G do" is about G's direct bindings only.
	}
}

func (c *subjectQueryContext) appendResolved(ref api.SubjectRef) {
	if slices.Contains(c.resolvedSubjects, ref) {
		return
	}
	c.resolvedSubjects = append(c.resolvedSubjects, ref)
	c.resolvedKeys = append(c.resolvedKeys, subjectKeyFromRef(ref))
}

// collect walks BindingsBySubject for each resolved key, deduplicates
// bindings by pointer identity (the same *BindingRecord is shared across
// indexes), resolves each binding's role, runs the matcher against the
// selector, and accumulates roleHits ordered for deterministic output.
func (c *subjectQueryContext) collect() {
	seen := make(map[*indexer.BindingRecord]api.SubjectRef)
	ordered := make([]*indexer.BindingRecord, 0)

	for i, key := range c.resolvedKeys {
		via := c.resolvedSubjects[i]
		for _, binding := range c.snapshot.BindingsBySubject[key] {
			if _, ok := seen[binding]; ok {
				continue
			}
			seen[binding] = via
			ordered = append(ordered, binding)
		}
	}

	for _, binding := range ordered {
		c.processBinding(binding, seen[binding])
	}
}

func (c *subjectQueryContext) processBinding(binding *indexer.BindingRecord, via api.SubjectRef) {
	roleID := indexer.RecID(binding.RoleRef.Kind, binding.RoleRef.Namespace, binding.RoleRef.Name)
	role, ok := c.snapshot.RolesByID[roleID]
	hit := c.ensureRoleHit(binding.RoleRef, role)

	hit.bindingAttrs = append(hit.bindingAttrs, bindingAttr{
		binding:    binding,
		viaSubject: via,
		scope:      effectiveScope(binding),
		broken:     !ok,
	})

	if !ok {
		c.addBrokenBindingWarning(binding, binding.RoleRef)

		return
	}

	if hit.matchedRefs == nil {
		hit.matchedRefs = c.matchRoleRules(role)
	}
}

func (c *subjectQueryContext) ensureRoleHit(ref indexer.RoleRefKey, role *indexer.RoleRecord) *roleHit {
	id := indexer.RecID(ref.Kind, ref.Namespace, ref.Name)
	if existing, ok := c.roleHitByID[id]; ok {
		if existing.role == nil && role != nil {
			existing.role = role
		}

		return existing
	}
	hit := &roleHit{role: role, refKey: ref}
	c.roleHitByID[id] = hit
	c.roleHits = append(c.roleHits, hit)

	return hit
}

// matchRoleRules applies the reverse-query selector to the role's rules and
// returns the matching RuleRefs. Wildcards follow c.wildcardMode.
func (c *subjectQueryContext) matchRoleRules(role *indexer.RoleRecord) []api.RuleRef {
	refs := make([]api.RuleRef, 0)
	for idx, rule := range role.Rules {
		result := matcher.MatchRule(matcher.MatchInput{
			Rule:         rule,
			Selector:     c.selector,
			Mode:         c.matchMode,
			WildcardMode: c.wildcardMode,
			SourceUID:    string(role.UID),
			RuleIndex:    idx,
		})
		if !result.Matched {
			continue
		}
		refs = append(refs, result.RuleRefs...)
	}

	return refs
}

// --- Warnings ---

func (c *subjectQueryContext) emitWarnings() {
	c.emitImpersonationWarnings()
	c.emitLargeResponseWarning()
}

func (c *subjectQueryContext) emitImpersonationWarnings() {
	var targets []api.SubjectRef
	for _, hit := range c.roleHits {
		if hit.role == nil {
			continue
		}
		for _, rule := range hit.role.Rules {
			if !containsCIString(rule.Verbs, impersonateVerb) && !containsCIString(rule.Verbs, "*") {
				continue
			}
			for _, resource := range rule.Resources {
				kind := impersonationKindForResource(resource)
				if kind == "" {
					continue
				}
				targets = appendImpersonationTargets(targets, kind, rule.ResourceNames)
			}
		}
	}
	if len(targets) == 0 {
		return
	}
	c.addWarning(api.SubjectWarning{
		Code:     api.SubjectWarningCodeImpersonationCapable,
		Message:  "subject can impersonate identities",
		Subjects: targets,
	})
}

func (c *subjectQueryContext) emitLargeResponseWarning() {
	if len(c.roleHits) <= subjectLargeResponseThreshold {
		return
	}
	c.addWarning(api.SubjectWarning{
		Code:      api.SubjectWarningCodeLargeResponse,
		Message:   fmt.Sprintf("aggregated %d roles", len(c.roleHits)),
		RoleCount: len(c.roleHits),
	})
}

func (c *subjectQueryContext) addBrokenBindingWarning(binding *indexer.BindingRecord, ref indexer.RoleRefKey) {
	br := bindingRefFromRecord(binding)
	rr := roleRefFromKey(ref)
	c.addWarning(api.SubjectWarning{
		Code:    api.SubjectWarningCodeBrokenBinding,
		Message: fmt.Sprintf("binding %s/%s references missing %s %s", binding.Kind, binding.Name, ref.Kind, roleRefDisplay(ref)),
		Binding: &br,
		RoleRef: &rr,
	})
}

func (c *subjectQueryContext) addWarning(w api.SubjectWarning) {
	key := warningDedupeKey(w)
	if _, ok := c.warningSeen[key]; ok {
		return
	}
	c.warningSeen[key] = struct{}{}
	c.warnings = append(c.warnings, w)
}

func warningDedupeKey(w api.SubjectWarning) string {
	var b strings.Builder
	b.WriteString(string(w.Code))
	b.WriteByte('|')
	b.WriteString(w.Message)
	if w.Binding != nil {
		b.WriteByte('|')
		b.WriteString(string(w.Binding.Kind))
		b.WriteByte('/')
		b.WriteString(w.Binding.Namespace)
		b.WriteByte('/')
		b.WriteString(w.Binding.Name)
	}

	return b.String()
}

// --- Helpers ---

func subjectKeyFromRef(ref api.SubjectRef) indexer.SubjectKey {
	return indexer.SubjectKey{
		Kind:      string(ref.Kind),
		Namespace: ref.Namespace,
		Name:      ref.Name,
	}
}

func effectiveScope(binding *indexer.BindingRecord) api.EffectiveScope {
	if binding.Kind == indexer.KindClusterRoleBinding {
		return api.EffectiveScopeCluster
	}

	return api.EffectiveScopeNamespaced
}

func bindingRefFromRecord(binding *indexer.BindingRecord) api.BindingRef {
	return api.BindingRef{
		Kind:      api.BindingKind(binding.Kind),
		Name:      binding.Name,
		Namespace: binding.Namespace,
	}
}

func roleRefFromRecord(role *indexer.RoleRecord) api.RoleRef {
	return api.RoleRef{
		Kind:      api.RoleRefKind(role.Kind),
		Name:      role.Name,
		Namespace: role.Namespace,
	}
}

func roleRefFromKey(ref indexer.RoleRefKey) api.RoleRef {
	return api.RoleRef{
		Kind:      api.RoleRefKind(ref.Kind),
		Name:      ref.Name,
		Namespace: ref.Namespace,
	}
}

func roleRefDisplay(ref indexer.RoleRefKey) string {
	if ref.Namespace != "" {
		return ref.Namespace + "/" + ref.Name
	}

	return ref.Name
}

func appendImpersonationTargets(targets []api.SubjectRef, kind api.SubjectKind, names []string) []api.SubjectRef {
	if len(names) == 0 {
		return appendUniqueSubjectRef(targets, api.SubjectRef{Kind: kind, Name: "*"})
	}
	for _, name := range names {
		targets = appendUniqueSubjectRef(targets, api.SubjectRef{Kind: kind, Name: name})
	}

	return targets
}

func appendUniqueSubjectRef(targets []api.SubjectRef, ref api.SubjectRef) []api.SubjectRef {
	if slices.Contains(targets, ref) {
		return targets
	}

	return append(targets, ref)
}

func impersonationKindForResource(resource string) api.SubjectKind {
	switch strings.ToLower(strings.TrimSpace(resource)) {
	case "users":
		return api.SubjectKindUser
	case "groups":
		return api.SubjectKindGroup
	case "serviceaccounts":
		return api.SubjectKindServiceAccount
	case "*":
		return api.SubjectKindUser
	default:
		return ""
	}
}

func containsCIString(slice []string, needle string) bool {
	for _, s := range slice {
		if strings.EqualFold(s, needle) {
			return true
		}
	}

	return false
}
