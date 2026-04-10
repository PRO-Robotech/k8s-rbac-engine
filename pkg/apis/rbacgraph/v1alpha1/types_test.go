package v1alpha1

import "testing"

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
