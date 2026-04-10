# rbac-engine

Kubernetes RBAC analytics platform: live graph querying + declarative policy-based auditing.

Single binary, two API groups, shared RBAC indexer.

## Features

- **RBAC Graph API** — Aggregated API endpoint for querying RBAC relationships as a directed graph (Role → Binding → Subject) with resource map aggregation
- **Declarative Policy Engine** — User-defined `RbacPolicy` CRDs with simple match rules and advanced conditions DSL (no Go code required)
- **Automated Reports** — `RbacReport` / `ClusterRbacReport` generated per Role/ClusterRole with severity summary and findings
- **Live Indexing** — In-memory RBAC snapshot via informers for Role, ClusterRole, RoleBinding, ClusterRoleBinding
- **14 Built-in Policies** — Security checks compatible with Trivy/Aqua KSV IDs (KSV041–KSV114)

## Architecture

```
rbac-engine (--mode=all|graph|reports)
├── Indexer (informers) ─── shared RBAC snapshot
│   ├── Aggregated API ─── rbacgraph.in-cloud.io/v1alpha1
│   │   └── POST rolegraphreviews (graph query + severity enrichment)
│   └── Reconcilers ─── rbacreports.in-cloud.io/v1alpha1
│       ├── Role/ClusterRole changed → evaluate policies → RbacReport
│       └── RbacPolicy changed → re-scan all roles
```

## API Groups

| API Group | Mechanism | Resources |
|-----------|-----------|-----------|
| `rbacgraph.in-cloud.io/v1alpha1` | Aggregated API | `RoleGraphReview` |
| `rbacreports.in-cloud.io/v1alpha1` | CRD | `RbacPolicy`, `RbacReport`, `ClusterRbacReport` |

## Quick Start

### Build

```bash
make docker-engine    # → rbac-engine:dev
```

### Deploy to kind

```bash
kind create cluster --name rbac-engine

# build → load → apply → wait → install 14 sample policies
make kind-install

# smoke checks
make kind-verify
```

Or, if you prefer manual control:

```bash
make docker-engine
kind load docker-image rbac-engine:dev --name rbac-engine
make build-installer                              # → dist/install.yaml
kubectl apply -f dist/install.yaml
kubectl -n rbac-engine-system rollout status deployment/rbac-engine
kubectl apply -k config/samples                   # 14 built-in policies
```

### Run modes

```bash
# All features (default)
rbac-engine --mode=all

# Graph API only (no reports)
rbac-engine --mode=graph

# Policy reports only (no aggregated API)
rbac-engine --mode=reports
```

### Verify

```bash
# Graph API
kubectl get apiservice v1alpha1.rbacgraph.in-cloud.io
kubectl get --raw /apis/rbacgraph.in-cloud.io/v1alpha1

# Policy reports
kubectl get rbacpolicies
kubectl get clusterrbacreports
kubectl get rbacreports -A
```

### Example: graph query

```bash
cat <<'JSON' | kubectl create --raw /apis/rbacgraph.in-cloud.io/v1alpha1/rolegraphreviews -f -
{
  "apiVersion": "rbacgraph.in-cloud.io/v1alpha1",
  "kind": "RoleGraphReview",
  "metadata": {"name": "demo"},
  "spec": {
    "selector": {
      "apiGroups": [""],
      "resources": ["pods/exec"],
      "verbs": ["get", "create"]
    },
    "matchMode": "any",
    "includeRuleMetadata": true
  }
}
JSON
```

### Example: custom policy

```yaml
apiVersion: rbacreports.in-cloud.io/v1alpha1
kind: RbacPolicy
metadata:
  name: no-secret-write
spec:
  severity: HIGH
  category: Kubernetes Security Check
  checkID: CUSTOM001
  title: Write access to secrets
  description: "Role has write access to secrets"
  remediation: "Remove write verbs for secrets"
  match:
    apiGroups: [""]
    resources: [secrets]
    verbs: [create, update, patch, delete, "*"]
  exclude:
    roleNames: ["system:*"]
```

## Built-in Policies

| CheckID | Severity | Title |
|---------|----------|-------|
| KSV041 | CRITICAL | Manage secrets (cluster-scope) |
| KSV044 | CRITICAL | No wildcard verb and resource roles |
| KSV045 | CRITICAL | No wildcard verb roles |
| KSV046 | CRITICAL | Manage all resources |
| KSV047 | HIGH | Privilege escalation from node proxy |
| KSV048 | MEDIUM | Manage Kubernetes workloads |
| KSV049 | MEDIUM | Manage configmaps |
| KSV050 | CRITICAL | Manage Kubernetes RBAC resources |
| KSV053 | HIGH | Exec into Pods |
| KSV056 | HIGH | Manage Kubernetes networking |
| KSV112 | CRITICAL | Manage all resources at namespace |
| KSV113 | MEDIUM | Manage namespace secrets |
| KSV114 | CRITICAL | Manage webhookconfigurations |

See `config/samples/` for full YAML definitions.

## Notes

- If informer caches are not synced yet, graph API returns `503 index_not_ready`.
- Reports use ownerReferences for automatic garbage collection when Role/ClusterRole is deleted.
- Report names replace `:` → `-` per RFC 1123. Original role name is in `spec.roleRef.name`.
