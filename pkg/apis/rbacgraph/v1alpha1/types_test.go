package v1alpha1

import (
	"encoding/json"
	"testing"
)

func TestRoleGraphReviewSpecEnsureDefaultsRuntime(t *testing.T) {
	spec := RoleGraphReviewSpec{}
	spec.EnsureDefaults()

	if spec.PodPhaseMode != PodPhaseModeActive {
		t.Fatalf("expected default podPhaseMode=%q, got %q", PodPhaseModeActive, spec.PodPhaseMode)
	}
	if spec.MaxPodsPerSubject != DefaultMaxPodsPerSubject {
		t.Fatalf("expected default maxPodsPerSubject=%d, got %d", DefaultMaxPodsPerSubject, spec.MaxPodsPerSubject)
	}
	if spec.MaxWorkloadsPerPod != DefaultMaxWorkloadsPerPod {
		t.Fatalf("expected default maxWorkloadsPerPod=%d, got %d", DefaultMaxWorkloadsPerPod, spec.MaxWorkloadsPerPod)
	}
}

func TestRoleGraphReviewSpecValidateRejectsInvalidPodPhaseMode(t *testing.T) {
	spec := RoleGraphReviewSpec{PodPhaseMode: PodPhaseMode("broken")}
	if err := spec.Validate(); err == nil {
		t.Fatalf("expected invalid podPhaseMode error")
	}
}

func TestRoleGraphReviewSpecNormalizeRuntimeFlags(t *testing.T) {
	spec := RoleGraphReviewSpec{
		IncludePods:      false,
		IncludeWorkloads: true,
	}
	warnings := spec.NormalizeRuntimeFlags()
	if !spec.IncludePods {
		t.Fatalf("expected includePods to be auto-enabled")
	}
	if len(warnings) != 1 {
		t.Fatalf("expected single warning, got %d", len(warnings))
	}
}

func TestSubjectPermissionsViewSpecEnsureDefaults(t *testing.T) {
	spec := SubjectPermissionsViewSpec{}
	spec.EnsureDefaults()

	if spec.MatchMode != MatchModeAny {
		t.Errorf("expected default matchMode=%q, got %q", MatchModeAny, spec.MatchMode)
	}
	if spec.WildcardMode != WildcardModeWildcard {
		t.Errorf("expected default wildcardMode=%q, got %q", WildcardModeWildcard, spec.WildcardMode)
	}
}

func TestSubjectViewEnsureDefaultsPopulatesTypeMeta(t *testing.T) {
	perm := &SubjectPermissionsView{Spec: SubjectPermissionsViewSpec{Subject: SubjectRef{Kind: SubjectKindUser, Name: "alice"}}}
	perm.EnsureDefaults()
	if perm.APIVersion != APIVersionValue {
		t.Errorf("expected apiVersion=%q, got %q", APIVersionValue, perm.APIVersion)
	}
	if perm.Kind != SubjectPermissionsViewKind {
		t.Errorf("expected kind=%q, got %q", SubjectPermissionsViewKind, perm.Kind)
	}

	graph := &SubjectGraphReview{Spec: SubjectGraphReviewSpec{Subject: SubjectRef{Kind: SubjectKindUser, Name: "alice"}}}
	graph.EnsureDefaults()
	if graph.APIVersion != APIVersionValue {
		t.Errorf("expected apiVersion=%q, got %q", APIVersionValue, graph.APIVersion)
	}
	if graph.Kind != SubjectGraphReviewKind {
		t.Errorf("expected kind=%q, got %q", SubjectGraphReviewKind, graph.Kind)
	}
}

func TestSubjectSpecValidate(t *testing.T) {
	tests := []struct {
		name    string
		subject SubjectRef
		wantErr bool
	}{
		{name: "service_account_ok", subject: SubjectRef{Kind: SubjectKindServiceAccount, Namespace: "team-a", Name: "foo"}},
		{name: "user_ok", subject: SubjectRef{Kind: SubjectKindUser, Name: "alice"}},
		{name: "group_ok", subject: SubjectRef{Kind: SubjectKindGroup, Name: "system:authenticated"}},
		{name: "missing_kind", subject: SubjectRef{Name: "x"}, wantErr: true},
		{name: "invalid_kind", subject: SubjectRef{Kind: "Robot", Name: "x"}, wantErr: true},
		{name: "missing_name", subject: SubjectRef{Kind: SubjectKindUser}, wantErr: true},
		{name: "sa_missing_namespace", subject: SubjectRef{Kind: SubjectKindServiceAccount, Name: "foo"}, wantErr: true},
		{name: "user_with_namespace", subject: SubjectRef{Kind: SubjectKindUser, Name: "alice", Namespace: "team-a"}, wantErr: true},
		{name: "group_with_namespace", subject: SubjectRef{Kind: SubjectKindGroup, Name: "g", Namespace: "ns"}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := SubjectPermissionsViewSpec{Subject: tt.subject}
			spec.EnsureDefaults()
			err := spec.Validate()
			if tt.wantErr && err == nil {
				t.Fatalf("expected validation error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			graphSpec := SubjectGraphReviewSpec{Subject: tt.subject}
			graphSpec.EnsureDefaults()
			if got := graphSpec.Validate(); (got != nil) != tt.wantErr {
				t.Fatalf("graph spec: want err=%v, got %v", tt.wantErr, got)
			}
		})
	}
}

func TestSubjectPermissionsViewJSONRoundTrip(t *testing.T) {
	orig := SubjectPermissionsView{
		Spec: SubjectPermissionsViewSpec{
			Subject:      SubjectRef{Kind: SubjectKindServiceAccount, Namespace: "team-a", Name: "foo"},
			MatchMode:    MatchModeAny,
			WildcardMode: WildcardModeWildcard,
			DirectOnly:   true,
		},
		Status: SubjectPermissionsViewStatus{
			Subject: SubjectRef{Kind: SubjectKindServiceAccount, Namespace: "team-a", Name: "foo"},
			ResolvedSubjects: []SubjectRef{
				{Kind: SubjectKindServiceAccount, Namespace: "team-a", Name: "foo"},
				{Kind: SubjectKindGroup, Name: "system:authenticated"},
			},
			APIGroups: []APIGroupPermissions{},
			Bindings: []SubjectBinding{{
				Kind:           BindingKindRoleBinding,
				Name:           "foo-rb",
				Namespace:      "team-a",
				RoleRef:        RoleRef{Kind: RoleRefKindClusterRole, Name: "view"},
				EffectiveScope: EffectiveScopeNamespaced,
				ViaSubject:     SubjectRef{Kind: SubjectKindServiceAccount, Namespace: "team-a", Name: "foo"},
			}},
			Roles: []SubjectRoleSummary{{Ref: RoleRef{Kind: RoleRefKindClusterRole, Name: "view"}}},
			Warnings: []SubjectWarning{{
				Code:    SubjectWarningCodeBrokenBinding,
				Message: "dangling role ref",
				Binding: &BindingRef{Kind: BindingKindRoleBinding, Name: "foo-rb", Namespace: "team-a"},
				RoleRef: &RoleRef{Kind: RoleRefKindClusterRole, Name: "deleted-role"},
			}},
			Grants: []AttributedGrant{{
				SourceRole:    RoleRef{Kind: RoleRefKindClusterRole, Name: "view"},
				SourceBinding: BindingRef{Kind: BindingKindRoleBinding, Name: "foo-rb", Namespace: "team-a"},
				APIGroup:      "",
				Resource:      "secrets",
				Verb:          "get",
			}},
		},
	}

	raw, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded SubjectPermissionsView
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Spec.Subject != orig.Spec.Subject {
		t.Errorf("spec.subject mismatch: want %v, got %v", orig.Spec.Subject, decoded.Spec.Subject)
	}
	if len(decoded.Status.Bindings) != 1 || decoded.Status.Bindings[0].EffectiveScope != EffectiveScopeNamespaced {
		t.Errorf("bindings mismatch: got %+v", decoded.Status.Bindings)
	}
	if len(decoded.Status.Warnings) != 1 || decoded.Status.Warnings[0].Code != SubjectWarningCodeBrokenBinding {
		t.Errorf("warnings mismatch: got %+v", decoded.Status.Warnings)
	}
	if decoded.Status.Warnings[0].Binding == nil || decoded.Status.Warnings[0].Binding.Name != "foo-rb" {
		t.Errorf("warning.binding mismatch: got %+v", decoded.Status.Warnings[0].Binding)
	}
	if len(decoded.Status.Grants) != 1 || decoded.Status.Grants[0].Resource != "secrets" || decoded.Status.Grants[0].Verb != "get" {
		t.Errorf("grants mismatch: got %+v", decoded.Status.Grants)
	}
}

func TestAttributedGrantJSONRoundTrip(t *testing.T) {
	grant := AttributedGrant{
		SourceRole:    RoleRef{Kind: RoleRefKindClusterRole, Name: "view"},
		SourceBinding: BindingRef{Kind: BindingKindClusterRoleBinding, Name: "view-crb"},
		APIGroup:      "",
		Resource:      "secrets",
		Verb:          "get",
		ResourceNames: []string{"my-secret"},
	}
	raw, err := json.Marshal(grant)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded AttributedGrant
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.SourceRole != grant.SourceRole || decoded.SourceBinding != grant.SourceBinding {
		t.Errorf("source mismatch: got role=%+v binding=%+v", decoded.SourceRole, decoded.SourceBinding)
	}
	if decoded.Resource != "secrets" || decoded.Verb != "get" {
		t.Errorf("payload mismatch: got %+v", decoded)
	}
	if len(decoded.ResourceNames) != 1 || decoded.ResourceNames[0] != "my-secret" {
		t.Errorf("resourceNames mismatch: got %v", decoded.ResourceNames)
	}
}
