package indexer

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func TestNormalizeServiceAccountName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{name: "empty", input: "", expected: DefaultServiceAccountName},
		{name: "spaces", input: "   ", expected: DefaultServiceAccountName},
		{name: "trim", input: " demo-sa ", expected: "demo-sa"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeServiceAccountName(tt.input)
			if got != tt.expected {
				t.Fatalf("expected %q, got %q", tt.expected, got)
			}
		})
	}
}

func TestRoleRefAndServiceAccountKeys(t *testing.T) {
	roleRef := RoleRefKey{
		Kind:      KindRole,
		Namespace: "team-a",
		Name:      "read-pods",
	}
	if roleRef.String() != "Role:team-a/read-pods" {
		t.Fatalf("unexpected RoleRefKey.String(): %q", roleRef.String())
	}

	saKey := serviceAccountKey("team-a", "demo-sa")
	if saKey.Namespace != "team-a" || saKey.Name != "demo-sa" {
		t.Fatalf("unexpected ServiceAccountKey: %#v", saKey)
	}
	if saKey.String() != "team-a/demo-sa" {
		t.Fatalf("unexpected ServiceAccountKey.String(): %q", saKey.String())
	}
}

func TestSnapshotTypedKeyMapsReadWrite(t *testing.T) {
	snapshot := newEmptySnapshot()
	ref := RoleRefKey{Kind: KindClusterRole, Name: "cluster-admin"}
	binding := &BindingRecord{Name: "bind-cluster-admin", RoleRef: ref}
	snapshot.BindingsByRoleRef[ref] = []*BindingRecord{binding}

	saKey := ServiceAccountKey{Namespace: "team-a", Name: "demo-sa"}
	pod := &PodRecord{Name: "pod-1", Namespace: "team-a", ServiceAccountName: "demo-sa"}
	snapshot.PodsByServiceAccount[saKey] = []*PodRecord{pod}

	if got := snapshot.BindingsByRoleRef[ref]; len(got) != 1 || got[0].Name != "bind-cluster-admin" {
		t.Fatalf("typed RoleRefKey map lookup failed: %#v", got)
	}
	if got := snapshot.PodsByServiceAccount[saKey]; len(got) != 1 || got[0].Name != "pod-1" {
		t.Fatalf("typed ServiceAccountKey map lookup failed: %#v", got)
	}
}

func TestIndexWorkloadStoresRecord(t *testing.T) {
	snapshot := newEmptySnapshot()
	indexWorkload(
		snapshot,
		"apps/v1",
		"Deployment",
		metav1.ObjectMeta{
			UID:       types.UID("uid-1"),
			Namespace: "team-a",
			Name:      "demo",
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "apps/v1",
				Kind:       "ReplicaSet",
				Name:       "demo-rs",
				UID:        types.UID("uid-rs"),
			}},
		},
	)

	got, ok := snapshot.WorkloadsByUID[types.UID("uid-1")]
	if !ok {
		t.Fatalf("expected workload record to be indexed")
	}
	if got.Kind != "Deployment" || got.Namespace != "team-a" || got.Name != "demo" {
		t.Fatalf("unexpected workload record: %#v", got)
	}
	if len(got.OwnerReferences) != 1 || got.OwnerReferences[0].Name != "demo-rs" {
		t.Fatalf("expected owner references to be preserved: %#v", got.OwnerReferences)
	}
}
