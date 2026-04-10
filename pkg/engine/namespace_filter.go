package engine

import (
	"strings"

	"k8s-rbac-engine/pkg/indexer"
)

func makeNamespaceFilter(namespaces []string) map[string]struct{} {
	filter := make(map[string]struct{}, len(namespaces))
	for _, ns := range namespaces {
		ns = strings.TrimSpace(ns)
		if ns == "" {
			continue
		}
		filter[ns] = struct{}{}
	}
	if len(filter) == 0 {
		return nil
	}

	return filter
}

func allowNamespace(filter map[string]struct{}, namespace string, strict bool) bool {
	if len(filter) == 0 {
		return true
	}
	if namespace == "" {
		return !strict
	}
	_, ok := filter[namespace]

	return ok
}

func filterBindingsByNamespace(filter map[string]struct{}, strict bool, bindings []*indexer.BindingRecord) []*indexer.BindingRecord {
	if len(filter) == 0 || len(bindings) == 0 {
		return bindings
	}
	out := make([]*indexer.BindingRecord, 0, len(bindings))
	for _, binding := range bindings {
		if binding.Namespace == "" {
			if !strict {
				out = append(out, binding)
			}

			continue
		}
		if _, ok := filter[binding.Namespace]; ok {
			out = append(out, binding)
		}
	}

	return out
}
