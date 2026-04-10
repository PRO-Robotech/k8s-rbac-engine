package indexer

import (
	"maps"
	"slices"
	"strings"
)

func RecID(kind, namespace, name string) RoleID {
	if namespace == "" {
		return RoleID(strings.ToLower(kind) + ":" + name)
	}

	return RoleID(strings.ToLower(kind) + ":" + namespace + "/" + name)
}

func cloneMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	maps.Copy(out, in)

	return out
}

func cloneSlice[T any](in []T) []T {
	if len(in) == 0 {
		return nil
	}

	return slices.Clone(in)
}

func serviceAccountKey(namespace, name string) ServiceAccountKey {
	return ServiceAccountKey{Namespace: namespace, Name: name}
}

func normalizeServiceAccountName(name string) string {
	normalized := strings.TrimSpace(name)
	if normalized == "" {
		return DefaultServiceAccountName
	}

	return normalized
}

func normalizedSlice(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	uniq := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, v := range values {
		n := strings.TrimSpace(strings.ToLower(v))
		if _, exists := uniq[n]; exists {
			continue
		}
		uniq[n] = struct{}{}
		out = append(out, n)
	}

	return out
}

func insertIndex(idx map[string]map[RoleID]struct{}, token string, roleID RoleID) {
	bucket, ok := idx[token]
	if !ok {
		bucket = make(map[RoleID]struct{})
		idx[token] = bucket
	}
	bucket[roleID] = struct{}{}
}
