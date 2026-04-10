SHELL := /bin/bash
GOCACHE := $(CURDIR)/.cache/go-build
GOMODCACHE := $(CURDIR)/.cache/go-mod

GOLANGCI_LINT_VERSION := v2.11.4

# Kind cluster name. Override on the command line:
#   make kind-install KIND_CLUSTER=my-cluster
KIND_CLUSTER ?= rbac-engine
NAMESPACE    ?= rbac-engine-system

.PHONY: fmt lint test generate manifests build-installer build docker-engine kustomize-kind openapi-spec verify-openapi-spec kind-install kind-uninstall kind-verify kind-load

# generate runs Go-code generation: deepcopy + conversion + openapi for the
# aggregated API, plus controller-gen object for the CRD types.
generate:
	./hack/update-codegen.sh

# manifests runs YAML generation: CRDs (from Go types) + ClusterRole (from
# +kubebuilder:rbac markers) + kustomization.yaml files (from filesystem
# discovery). After this target, every file under deploy/kustomize/base/
# is either checked-in static YAML (manager.yaml, service_account.yaml,
# role_binding.yaml) or freshly regenerated.
manifests:
	./hack/update-manifests.sh

# build-installer takes the kind overlay and merges all base + overlay
# resources into a single dist/install.yaml ready for `kubectl apply -f`.
# Depends on `manifests` so the source YAMLs are up to date.
build-installer: manifests
	mkdir -p dist
	kubectl kustomize deploy/kustomize/overlays/kind > dist/install.yaml
	@echo ">>> Wrote dist/install.yaml"

fmt:
	gofmt -w $$(find cmd internal pkg hack -name '*.go')

lint:
	@which golangci-lint > /dev/null 2>&1 || \
		go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	golangci-lint run ./...

test:
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) go test ./...

build:
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) go build -o bin/rbac-engine ./cmd/rbac-engine

docker-engine:
	docker build -t rbac-engine:dev .

kustomize-kind:
	kubectl kustomize deploy/kustomize/overlays/kind

openapi-spec:
	go run ./hack/openapi-spec > api/openapi-spec/swagger.json

verify-openapi-spec:
	@diff <(go run ./hack/openapi-spec) api/openapi-spec/swagger.json || \
	  (echo "api/openapi-spec/swagger.json is stale — run 'make openapi-spec'" && exit 1)

# ───────────────────────────────────────────────────────────────────────────
# Kind local-test deploy
#
# Prerequisite: a kind cluster already exists. Create one with:
#   kind create cluster --name $(KIND_CLUSTER)
#
# kind-load        builds the docker image and loads it into the cluster
# kind-install     full deploy: load → apply → wait ready → install samples
# kind-verify      smoke checks: APIService Available, deployment ready,
#                  policies + reports present, sample graph query works
# kind-uninstall   tears down the install (manifests + samples). Does NOT
#                  delete the kind cluster itself.
# ───────────────────────────────────────────────────────────────────────────

kind-load: docker-engine
	kind load docker-image rbac-engine:dev --name $(KIND_CLUSTER)

kind-install: kind-load build-installer
	kubectl apply -f dist/install.yaml
	@echo ">>> Waiting for rbac-engine deployment to be ready..."
	kubectl -n $(NAMESPACE) rollout status deployment/rbac-engine --timeout=120s
	@echo ">>> Waiting for v1alpha1.rbacgraph.incloud.io APIService..."
	kubectl wait --for=condition=Available --timeout=120s \
	    apiservice/v1alpha1.rbacgraph.incloud.io
	@echo ">>> Installing built-in policies (config/samples/)..."
	kubectl apply -k config/samples
	@echo ">>> Done. Run 'make kind-verify' for smoke checks."

kind-uninstall:
	-kubectl delete -k config/samples --ignore-not-found
	-kubectl delete -f dist/install.yaml --ignore-not-found

kind-verify:
	@echo ">>> APIService availability"
	kubectl get apiservice v1alpha1.rbacgraph.incloud.io
	@echo
	@echo ">>> Deployment status"
	kubectl -n $(NAMESPACE) get deployment rbac-engine
	@echo
	@echo ">>> RbacPolicy objects (expect 14 built-in)"
	kubectl get rbacpolicies --no-headers | wc -l
	@echo
	@echo ">>> ClusterRbacReport objects (one per ClusterRole)"
	kubectl get clusterrbacreports --no-headers 2>/dev/null | wc -l
	@echo
	@echo ">>> RbacReport objects (one per Role, all namespaces)"
	kubectl get rbacreports -A --no-headers 2>/dev/null | wc -l
	@echo
	@echo ">>> Sample aggregated API query: roles granting access to secrets"
	@printf '%s' '{"apiVersion":"rbacgraph.incloud.io/v1alpha1","kind":"RoleGraphReview","spec":{"selector":{"resources":["secrets"],"verbs":["get"]}}}' \
	  | kubectl create --raw /apis/rbacgraph.incloud.io/v1alpha1/rolegraphreviews -f - \
	  | python3 -c 'import json,sys; d=json.load(sys.stdin); nodes=d["status"]["graph"]["nodes"]; enriched=sum(1 for n in nodes if n.get("assessment")); print("    matched", len(nodes), "nodes,", enriched, "with assessment")' \
	  || echo "    (graph query failed — check operator logs)"
