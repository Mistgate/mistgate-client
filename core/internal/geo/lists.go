package geo

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
)

// ListInfo is one row of routes.lists.
type ListInfo struct {
	ID          string `json:"id"`
	Entries     int    `json:"entries"`
	UpdatedUnix int64  `json:"updated_unix"`
	Error       string `json:"error"` // code of the last failed download; empty when the last one worked
}

// Lists is the answer of routes.lists.
type Lists struct {
	Lists      []ListInfo `json:"lists"`
	Unique     int        `json:"unique"`     // distinct entries over all site collections, the region list not counted
	Duplicates int        `json:"duplicates"` // entries of the collections summed, minus unique
}

// Update downloads the region list (when region is a country code) and every collection the rules name, now,
// whatever their age. A list that fails keeps its old copy and its error. A second call while one runs waits for
// it instead of downloading again.
func (s *Store) Update(ctx context.Context, region string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	if running := s.updating; running != nil {
		s.mu.Unlock()
		select {
		case <-running:
		case <-ctx.Done():
		}
		return
	}
	done := make(chan struct{})
	s.updating = done
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.updating = nil
		s.mu.Unlock()
		close(done)
	}()
	ctx, cancel := context.WithTimeout(ctx, updateTimeout)
	defer cancel()

	var group sync.WaitGroup
	var sitesChanged atomic.Bool
	if ValidRegion(region) {
		group.Go(func() { s.pullRegion(ctx, region) })
	}
	for _, collection := range ruleCollections(s.GetRules()) {
		path, _, ok := siteCachePath(s.dir, collection)
		if !ok {
			continue
		}
		group.Go(func() {
			if s.pullSites(ctx, collection, path) {
				sitesChanged.Store(true)
			}
		})
	}
	group.Wait()
	if sitesChanged.Load() {
		s.rebuildSiteRules()
	}
	// also after a failure: the errors in routes.lists changed
	s.signalChange()
}

// Lists describes the lists in use: the region of the last Routes() call and the collections of the rules. It reads
// memory and file times only, never the network.
func (s *Store) Lists() Lists {
	result := Lists{Lists: []ListInfo{}}
	if s == nil {
		return result
	}
	collections := ruleCollections(s.GetRules())
	sets := make([]*SiteSet, 0, len(collections))
	paths := make([]string, 0, len(collections)+1)
	s.mu.Lock()
	if cc := s.effective; ValidRegion(cc) {
		id := "region:" + cc
		result.Lists = append(result.Lists, ListInfo{ID: id, Entries: s.sets[cc].PrefixCount(), Error: s.errs[id]})
		paths = append(paths, filepath.Join(s.dir, cc+".list"))
	}
	for _, collection := range collections {
		set := s.siteSets[collection]
		sets = append(sets, set)
		result.Lists = append(result.Lists, ListInfo{ID: collection, Entries: set.Len(), Error: s.errs[collection]})
		paths = append(paths, s.sitePath(collection))
	}
	s.mu.Unlock()
	for i, path := range paths { // file times, outside the lock
		if info, err := os.Stat(path); err == nil {
			result.Lists[i].UpdatedUnix = info.ModTime().Unix()
		}
	}
	total := 0
	for _, set := range sets {
		total += set.Len()
	}
	result.Unique = s.uniqueEntries(sets)
	result.Duplicates = total - result.Unique
	return result
}

// uniqueEntries counts the distinct domains over the sets. A set is never changed after it is built (a refresh swaps
// the pointer), so the count is kept until one of the pointers changes.
func (s *Store) uniqueEntries(sets []*SiteSet) int {
	s.mu.Lock()
	if slices.Equal(sets, s.uniqueSets) {
		n := s.uniqueCount
		s.mu.Unlock()
		return n
	}
	s.mu.Unlock()
	seen := make(map[string]struct{})
	for _, set := range sets {
		if set != nil {
			for domain := range set.domains {
				seen[domain] = struct{}{}
			}
		}
	}
	s.mu.Lock()
	s.uniqueSets, s.uniqueCount = sets, len(seen)
	s.mu.Unlock()
	return len(seen)
}
