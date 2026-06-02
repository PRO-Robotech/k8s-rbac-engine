package indexer

import (
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
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

func TestSubjectKey_String(t *testing.T) {
	tests := []struct {
		name     string
		key      SubjectKey
		expected string
	}{
		{name: "user", key: SubjectKey{Kind: SubjectKindUser, Name: "alice"}, expected: "User:alice"},
		{name: "group", key: SubjectKey{Kind: SubjectKindGroup, Name: "system:authenticated"}, expected: "Group:system:authenticated"},
		{name: "service_account_with_namespace", key: SubjectKey{Kind: SubjectKindServiceAccount, Namespace: "default", Name: "foo"}, expected: "ServiceAccount:default/foo"},
		{name: "service_account_no_namespace", key: SubjectKey{Kind: SubjectKindServiceAccount, Name: "foo"}, expected: "ServiceAccount:foo"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.key.String(); got != tt.expected {
				t.Fatalf("expected %q, got %q", tt.expected, got)
			}
		})
	}
}

func TestSubjectKeyConstructor(t *testing.T) {
	tests := []struct {
		name             string
		subject          rbacv1.Subject
		bindingNamespace string
		expected         SubjectKey
	}{
		{
			name:             "service_account_explicit_namespace_preserved",
			subject:          rbacv1.Subject{Kind: SubjectKindServiceAccount, Namespace: "kube-system", Name: "foo"},
			bindingNamespace: "other",
			expected:         SubjectKey{Kind: SubjectKindServiceAccount, Namespace: "kube-system", Name: "foo"},
		},
		{
			name:             "bare_service_account_inherits_binding_namespace",
			subject:          rbacv1.Subject{Kind: SubjectKindServiceAccount, Name: "foo"},
			bindingNamespace: "team-a",
			expected:         SubjectKey{Kind: SubjectKindServiceAccount, Namespace: "team-a", Name: "foo"},
		},
		{
			name:             "user_ignores_binding_namespace",
			subject:          rbacv1.Subject{Kind: SubjectKindUser, Name: "alice"},
			bindingNamespace: "team-a",
			expected:         SubjectKey{Kind: SubjectKindUser, Name: "alice"},
		},
		{
			name:             "group_ignores_binding_namespace",
			subject:          rbacv1.Subject{Kind: SubjectKindGroup, Name: "dev-team"},
			bindingNamespace: "team-a",
			expected:         SubjectKey{Kind: SubjectKindGroup, Name: "dev-team"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := subjectKey(tt.subject, tt.bindingNamespace); got != tt.expected {
				t.Fatalf("expected %#v, got %#v", tt.expected, got)
			}
		})
	}
}

func TestIndexBindingRecord_PopulatesSubjectIndex(t *testing.T) {
	snapshot := newEmptySnapshot()
	indexBindingRecord(snapshot,
		types.UID("bind-1"),
		KindRoleBinding,
		"team-a",
		"pod-reader-binding",
		rbacv1.RoleRef{Kind: KindRole, Name: "pod-reader"},
		[]rbacv1.Subject{
			{Kind: SubjectKindServiceAccount, Namespace: "team-a", Name: "sa-1"},
			{Kind: SubjectKindUser, Name: "alice"},
			{Kind: SubjectKindGroup, Name: "dev-team"},
			{Kind: SubjectKindServiceAccount, Name: "default-sa"},
		},
	)

	refKey := RoleRefKey{Kind: KindRole, Namespace: "team-a", Name: "pod-reader"}
	if bindings := snapshot.BindingsByRoleRef[refKey]; len(bindings) != 1 {
		t.Fatalf("expected 1 binding in BindingsByRoleRef, got %d", len(bindings))
	}

	expected := []SubjectKey{
		{Kind: SubjectKindServiceAccount, Namespace: "team-a", Name: "sa-1"},
		{Kind: SubjectKindUser, Name: "alice"},
		{Kind: SubjectKindGroup, Name: "dev-team"},
		{Kind: SubjectKindServiceAccount, Namespace: "team-a", Name: "default-sa"},
	}
	for _, sk := range expected {
		bindings, ok := snapshot.BindingsBySubject[sk]
		if !ok {
			t.Errorf("expected subject %s to be indexed", sk)

			continue
		}
		if len(bindings) != 1 || bindings[0].Name != "pod-reader-binding" {
			t.Errorf("unexpected bindings for %s: %#v", sk, bindings)
		}
	}

	if got := len(snapshot.BindingsBySubject); got != len(expected) {
		t.Errorf("expected %d subject keys, got %d", len(expected), got)
	}
}

func TestIndexBindingRecord_MultipleBindingsSameSubject(t *testing.T) {
	snapshot := newEmptySnapshot()
	subject := rbacv1.Subject{Kind: SubjectKindServiceAccount, Namespace: "team-a", Name: "sa-1"}

	indexBindingRecord(snapshot, types.UID("b1"), KindRoleBinding, "team-a", "bind-1",
		rbacv1.RoleRef{Kind: KindRole, Name: "role-a"}, []rbacv1.Subject{subject})
	indexBindingRecord(snapshot, types.UID("b2"), KindRoleBinding, "team-a", "bind-2",
		rbacv1.RoleRef{Kind: KindClusterRole, Name: "role-b"}, []rbacv1.Subject{subject})

	sk := SubjectKey{Kind: SubjectKindServiceAccount, Namespace: "team-a", Name: "sa-1"}
	bindings := snapshot.BindingsBySubject[sk]
	if len(bindings) != 2 {
		t.Fatalf("expected 2 bindings for shared subject, got %d", len(bindings))
	}
}
