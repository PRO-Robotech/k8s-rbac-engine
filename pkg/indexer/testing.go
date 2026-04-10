package indexer

// SetSnapshotForTest replaces the current snapshot. Intended for use in tests only.
func (i *Indexer) SetSnapshotForTest(s *Snapshot) {
	i.snapshot.Store(s)
}

// SetDiscoveryCacheForTest replaces the current discovery cache. Intended for
// use in tests only — production code refreshes the cache from the discovery
// client on a timer.
func (i *Indexer) SetDiscoveryCacheForTest(c *APIDiscoveryCache) {
	if c == nil {
		return
	}
	i.discoveryCache.Store(c)
}
