package indexer

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"k8s.io/client-go/discovery"
	"k8s.io/klog/v2"

	api "k8s-rbac-engine/pkg/apis/rbacgraph"
)

// APIDiscoveryCache holds the set of valid API groups, resources, and verbs
// known to the cluster. It is rebuilt periodically from the discovery API.
type APIDiscoveryCache struct {
	Groups               map[string]struct{}            // valid apiGroup names ("", "apps", "batch")
	ResourcesByGroup     map[string]map[string]struct{} // apiGroup → resource names (incl. subresources "pods/exec")
	VerbsByGroupResource map[string]map[string][]string // apiGroup → resource → sorted verbs
	AllResources         map[string]struct{}
	AllVerbs             map[string]struct{}
	FetchedAt            time.Time
}

func buildDiscoveryCache(client discovery.DiscoveryInterface) (*APIDiscoveryCache, error) {
	_, resourceLists, err := client.ServerGroupsAndResources()
	if err != nil {
		if resourceLists == nil {
			return nil, fmt.Errorf("server groups and resources: %w", err)
		}
		klog.Warningf("partial discovery error (continuing with available data): %v", err)
	}

	cache := &APIDiscoveryCache{
		Groups:               make(map[string]struct{}),
		ResourcesByGroup:     make(map[string]map[string]struct{}),
		VerbsByGroupResource: make(map[string]map[string][]string),
		AllResources:         make(map[string]struct{}),
		AllVerbs:             make(map[string]struct{}),
		FetchedAt:            time.Now().UTC(),
	}

	for _, list := range resourceLists {
		group := groupFromGroupVersion(list.GroupVersion)
		cache.Groups[group] = struct{}{}

		if _, ok := cache.ResourcesByGroup[group]; !ok {
			cache.ResourcesByGroup[group] = make(map[string]struct{})
		}
		if _, ok := cache.VerbsByGroupResource[group]; !ok {
			cache.VerbsByGroupResource[group] = make(map[string][]string)
		}

		for i := range list.APIResources {
			r := &list.APIResources[i]
			cache.ResourcesByGroup[group][r.Name] = struct{}{}
			cache.AllResources[r.Name] = struct{}{}

			verbs := make([]string, len(r.Verbs))
			for j, v := range r.Verbs {
				lv := strings.ToLower(v)
				verbs[j] = lv
				cache.AllVerbs[lv] = struct{}{}
			}
			sort.Strings(verbs)
			cache.VerbsByGroupResource[group][r.Name] = verbs
		}
	}

	return cache, nil
}

func groupFromGroupVersion(gv string) string {
	if group, _, ok := strings.Cut(gv, "/"); ok {
		return group
	}

	return ""
}

func (i *Indexer) refreshDiscoveryLoop(stopCh <-chan struct{}, interval time.Duration) {
	i.tryRefreshDiscovery("initial discovery cache build failed: %v")

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
			i.tryRefreshDiscovery("discovery cache refresh failed (keeping stale): %v")
		}
	}
}

func (i *Indexer) tryRefreshDiscovery(errFmt string) {
	c, err := buildDiscoveryCache(i.discoveryClient)
	if err != nil {
		klog.Warningf(errFmt, err)

		return
	}
	i.discoveryCache.Store(c)
}

// ValidateSelector checks selector values against the cluster's API discovery data.
func (i *Indexer) ValidateSelector(sel api.Selector) error {
	cache := i.discoveryCache.Load()
	if cache == nil {
		return nil // graceful degradation
	}

	if err := validateAPIGroups(cache, sel.APIGroups); err != nil {
		return err
	}
	if err := validateResources(cache, sel.APIGroups, sel.Resources); err != nil {
		return err
	}
	if err := validateVerbs(cache, sel.Verbs); err != nil {
		return err
	}

	return nil
}

func validateAPIGroups(cache *APIDiscoveryCache, apiGroups []string) error {
	if len(apiGroups) == 0 || containsWildcard(apiGroups) {
		return nil
	}
	var unknown []string
	for _, g := range apiGroups {
		if _, ok := cache.Groups[g]; !ok {
			unknown = append(unknown, g)
		}
	}
	if len(unknown) > 0 {
		return fmt.Errorf("unknown apiGroups: %q; use 'kubectl api-resources' to list available groups", unknown)
	}

	return nil
}

func validateResources(cache *APIDiscoveryCache, apiGroups, resources []string) error {
	if len(resources) == 0 || containsWildcard(resources) {
		return nil
	}

	// When apiGroups are constrained, each resource must exist in at least one specified group.
	// When apiGroups are unconstrained (empty or wildcard), check AllResources.
	constrained := len(apiGroups) > 0 && !containsWildcard(apiGroups)

	var unknown []string
	for _, r := range resources {
		if constrained {
			if !resourceExistsInGroups(cache, apiGroups, r) {
				unknown = append(unknown, r)
			}
		} else if _, ok := cache.AllResources[r]; !ok {
			unknown = append(unknown, r)
		}
	}
	if len(unknown) > 0 {
		return fmt.Errorf("unknown resources: %q; use 'kubectl api-resources' to list available resources", unknown)
	}

	return nil
}

func resourceExistsInGroups(cache *APIDiscoveryCache, apiGroups []string, resource string) bool {
	for _, g := range apiGroups {
		if grp, ok := cache.ResourcesByGroup[g]; ok {
			if _, ok := grp[resource]; ok {
				return true
			}
		}
	}

	return false
}

func validateVerbs(cache *APIDiscoveryCache, verbs []string) error {
	if len(verbs) == 0 || containsWildcard(verbs) {
		return nil
	}
	var unknown []string
	for _, v := range verbs {
		if _, ok := cache.AllVerbs[strings.ToLower(v)]; !ok {
			unknown = append(unknown, v)
		}
	}
	if len(unknown) > 0 {
		return fmt.Errorf("unknown verbs: %q; use 'kubectl api-resources -o wide' to list available verbs", unknown)
	}

	return nil
}

func containsWildcard(values []string) bool {
	return slices.Contains(values, "*")
}
