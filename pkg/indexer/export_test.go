package indexer

import rbacv1 "k8s.io/api/rbac/v1"

var NewEmptySnapshotForTest = newEmptySnapshot
var SortSnapshotForTest = sortSnapshot

func IndexRoleTokensForTest(s *Snapshot, roleID RoleID, rules []rbacv1.PolicyRule) {
	indexRoleTokens(s, roleID, rules)
}
