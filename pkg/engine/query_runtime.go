package engine

import (
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	api "k8s-rbac-engine/pkg/apis/rbacgraph"
	"k8s-rbac-engine/pkg/indexer"
)

//nolint:gocognit,gocyclo,funlen // runtime chain expansion has necessary branching
func (qc *queryContext) expandRuntimeChain() {
	if !qc.spec.IncludePods {
		return
	}
	for _, subject := range sortedServiceAccounts(qc.saSubjects) {
		if subject.Namespace == "" {
			qc.addWarning(fmt.Sprintf("subject %s has empty namespace and was skipped for runtime expansion", subject.SubjectNodeID))

			continue
		}
		if !allowNamespace(qc.namespaceFilter, subject.Namespace, qc.namespaceStrict) {
			continue
		}
		podRecords := qc.filterPods(qc.snapshot.PodsByServiceAccount[subject.ServiceAccountKey()])
		if len(podRecords) == 0 {
			continue
		}

		visiblePods := podRecords
		if len(visiblePods) > qc.spec.MaxPodsPerSubject {
			visiblePods = visiblePods[:qc.spec.MaxPodsPerSubject]
		}
		for _, pod := range visiblePods {
			podNodeIDValue := podNodeID(pod)
			if qc.addNodeIfMissing(api.GraphNode{
				ID:        podNodeIDValue,
				Type:      api.GraphNodeTypePod,
				Name:      pod.Name,
				Namespace: pod.Namespace,
				PodPhase:  string(pod.Phase),
			}) {
				qc.podSeen[podNodeIDValue] = struct{}{}
			}
			qc.appendEdgeIfMissing(api.GraphEdge{
				ID:      edgeIDFor(subject.SubjectNodeID, podNodeIDValue, api.GraphEdgeTypeRunsAs),
				From:    subject.SubjectNodeID,
				To:      podNodeIDValue,
				Type:    api.GraphEdgeTypeRunsAs,
				Explain: edgeExplainRunsAs,
			})

			if !qc.spec.IncludeWorkloads {
				continue
			}

			workloadChain := qc.resolveWorkloadChain(pod)
			visibleChain := workloadChain
			if len(visibleChain) > qc.spec.MaxWorkloadsPerPod {
				visibleChain = visibleChain[:qc.spec.MaxWorkloadsPerPod]
			}

			parentID := podNodeIDValue
			for _, workload := range visibleChain {
				workloadNodeIDValue := workloadNodeID(workload)
				if qc.addNodeIfMissing(api.GraphNode{
					ID:           workloadNodeIDValue,
					Type:         api.GraphNodeTypeWorkload,
					Name:         workload.Name,
					Namespace:    workload.Namespace,
					WorkloadKind: workload.Kind,
				}) {
					qc.workloadSeen[workloadNodeIDValue] = struct{}{}
				}
				qc.appendEdgeIfMissing(api.GraphEdge{
					ID:      edgeIDFor(parentID, workloadNodeIDValue, api.GraphEdgeTypeOwnedBy),
					From:    parentID,
					To:      workloadNodeIDValue,
					Type:    api.GraphEdgeTypeOwnedBy,
					Explain: edgeExplainOwnedBy,
				})
				parentID = workloadNodeIDValue
			}

			hiddenWorkloads := len(workloadChain) - len(visibleChain)
			if hiddenWorkloads > 0 {
				overflowID := workloadOverflowNodeID(podNodeIDValue)
				qc.addNodeIfMissing(api.GraphNode{
					ID:          overflowID,
					Type:        api.GraphNodeTypeWorkloadOverflow,
					Name:        fmt.Sprintf("+%d workloads", hiddenWorkloads),
					Namespace:   pod.Namespace,
					Synthetic:   true,
					HiddenCount: hiddenWorkloads,
				})
				qc.appendEdgeIfMissing(api.GraphEdge{
					ID:      edgeIDFor(parentID, overflowID, api.GraphEdgeTypeOwnedBy),
					From:    parentID,
					To:      overflowID,
					Type:    api.GraphEdgeTypeOwnedBy,
					Explain: "Workload chain truncated by limit",
				})
			}
		}

		hiddenPods := len(podRecords) - len(visiblePods)
		if hiddenPods > 0 {
			overflowID := podOverflowNodeID(subject.SubjectNodeID)
			qc.addNodeIfMissing(api.GraphNode{
				ID:          overflowID,
				Type:        api.GraphNodeTypePodOverflow,
				Name:        fmt.Sprintf("+%d pods", hiddenPods),
				Namespace:   subject.Namespace,
				Synthetic:   true,
				HiddenCount: hiddenPods,
			})
			qc.appendEdgeIfMissing(api.GraphEdge{
				ID:      edgeIDFor(subject.SubjectNodeID, overflowID, api.GraphEdgeTypeRunsAs),
				From:    subject.SubjectNodeID,
				To:      overflowID,
				Type:    api.GraphEdgeTypeRunsAs,
				Explain: "Pod list truncated by limit",
			})
		}
	}
}

type subjectServiceAccount struct {
	SubjectNodeID      string
	Namespace          string
	ServiceAccountName string
}

func (s subjectServiceAccount) ServiceAccountKey() indexer.ServiceAccountKey {
	return indexer.ServiceAccountKey{
		Namespace: s.Namespace,
		Name:      s.ServiceAccountName,
	}
}

func (qc *queryContext) trackServiceAccountSubject(subjectNodeID string, subject rbacv1.Subject, bindingNamespace string) {
	if subjectType(subject.Kind) != api.GraphNodeTypeServiceAccount {
		return
	}
	namespace := strings.TrimSpace(subject.Namespace)
	if namespace == "" {
		namespace = strings.TrimSpace(bindingNamespace)
	}
	qc.saSubjects[subjectNodeID] = subjectServiceAccount{
		SubjectNodeID:      subjectNodeID,
		Namespace:          namespace,
		ServiceAccountName: subject.Name,
	}
}

func sortedServiceAccounts(subjects map[string]subjectServiceAccount) []subjectServiceAccount {
	if len(subjects) == 0 {
		return nil
	}
	out := make([]subjectServiceAccount, 0, len(subjects))
	for _, subject := range subjects {
		out = append(out, subject)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Namespace != out[j].Namespace {
			return out[i].Namespace < out[j].Namespace
		}
		if out[i].ServiceAccountName != out[j].ServiceAccountName {
			return out[i].ServiceAccountName < out[j].ServiceAccountName
		}

		return out[i].SubjectNodeID < out[j].SubjectNodeID
	})

	return out
}

func (qc *queryContext) filterPods(pods []*indexer.PodRecord) []*indexer.PodRecord {
	if len(pods) == 0 {
		return nil
	}
	out := make([]*indexer.PodRecord, 0, len(pods))
	for _, pod := range pods {
		if pod == nil {
			continue
		}
		if !allowNamespace(qc.namespaceFilter, pod.Namespace, qc.namespaceStrict) {
			continue
		}
		if !podPhaseMatches(pod.Phase, qc.spec.PodPhaseMode) {
			continue
		}
		out = append(out, pod)
	}

	return out
}

func podPhaseMatches(phase corev1.PodPhase, mode api.PodPhaseMode) bool {
	switch mode {
	case api.PodPhaseModeAll:
		return true
	case api.PodPhaseModeRunning:
		return phase == corev1.PodRunning
	default:
		return phase == corev1.PodPending || phase == corev1.PodRunning || phase == corev1.PodUnknown
	}
}

func (qc *queryContext) addWarning(msg string) {
	appendUniqueString(&qc.status.Warnings, qc.warningSeen, msg)
}

func (qc *queryContext) resolveWorkloadChain(pod *indexer.PodRecord) []*indexer.WorkloadRecord {
	if pod == nil {
		return nil
	}
	owner, ok := chooseOwnerReference(pod.OwnerReferences)
	if !ok {
		qc.addWarning(fmt.Sprintf("pod %s/%s has no owner reference; workload chain cannot be expanded", pod.Namespace, pod.Name))

		return nil
	}

	const maxOwnerDepth = 8
	chain := make([]*indexer.WorkloadRecord, 0, maxOwnerDepth)
	seenUIDs := make(map[types.UID]struct{}, maxOwnerDepth)
	currentOwner := owner
	for range maxOwnerDepth {
		if currentOwner.UID == "" {
			qc.addWarning(fmt.Sprintf("pod %s/%s owner reference %s/%s has empty UID", pod.Namespace, pod.Name, currentOwner.Kind, currentOwner.Name))

			return chain
		}
		if _, exists := seenUIDs[currentOwner.UID]; exists {
			qc.addWarning(fmt.Sprintf("pod %s/%s owner chain has cycle at UID %s", pod.Namespace, pod.Name, currentOwner.UID))

			return chain
		}
		seenUIDs[currentOwner.UID] = struct{}{}

		workload, exists := qc.snapshot.WorkloadsByUID[currentOwner.UID]
		if !exists {
			qc.addWarning(fmt.Sprintf(
				"pod %s/%s owner %s/%s (%s) not found in workload cache",
				pod.Namespace,
				pod.Name,
				currentOwner.Kind,
				currentOwner.Name,
				currentOwner.UID,
			))

			return chain
		}
		chain = append(chain, workload)

		nextOwner, hasNext := chooseOwnerReference(workload.OwnerReferences)
		if !hasNext {
			return chain
		}
		currentOwner = nextOwner
	}

	qc.addWarning(fmt.Sprintf("pod %s/%s owner chain was truncated at depth %d", pod.Namespace, pod.Name, maxOwnerDepth))

	return chain
}

func chooseOwnerReference(ownerReferences []metav1.OwnerReference) (metav1.OwnerReference, bool) {
	if len(ownerReferences) == 0 {
		return metav1.OwnerReference{}, false
	}
	if len(ownerReferences) == 1 {
		return ownerReferences[0], true
	}
	candidates := append([]metav1.OwnerReference(nil), ownerReferences...)
	sort.Slice(candidates, func(i, j int) bool {
		left := candidates[i]
		right := candidates[j]
		leftController := left.Controller != nil && *left.Controller
		rightController := right.Controller != nil && *right.Controller
		if leftController != rightController {
			return leftController
		}

		return ownerRefSortKey(left) < ownerRefSortKey(right)
	})

	return candidates[0], true
}

func ownerRefSortKey(ref metav1.OwnerReference) string {
	return strings.ToLower(ref.APIVersion) + "|" + strings.ToLower(ref.Kind) + "|" + strings.ToLower(ref.Name) + "|" + string(ref.UID)
}
