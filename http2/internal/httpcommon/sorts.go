package httpcommon

import (
	"net/http"
	"sort"
	"strings"
	"sync"
)

// A headerSorter implements sort.Interface by sorting a []keyValues
// by the given order, if not nil, or by Key otherwise.
// It's used as a pointer, so it can fit in a sort.Interface
// value without allocation.
type headerSorter struct {
	keys  []string
	order map[string]int
}

func (s *headerSorter) Len() int      { return len(s.keys) }
func (s *headerSorter) Swap(i, j int) { s.keys[i], s.keys[j] = s.keys[j], s.keys[i] }
func (s *headerSorter) Less(i, j int) bool {
	// If the order isn't defined, sort lexicographically.
	if len(s.order) == 0 {
		return s.keys[i] < s.keys[j]
	}
	si, iok := s.order[strings.ToLower(s.keys[i])]
	sj, jok := s.order[strings.ToLower(s.keys[j])]
	if !iok && !jok {
		return s.keys[i] < s.keys[j]
	} else if !iok && jok {
		return false
	} else if iok && !jok {
		return true
	}
	return si < sj
}

var headerSorterPool = sync.Pool{
	New: func() any { return new(headerSorter) },
}

func sortedKeyValues(header http.Header) (keys []string) {
	sorter := headerSorterPool.Get().(*headerSorter)
	defer headerSorterPool.Put(sorter)

	if cap(sorter.keys) < len(header) {
		sorter.keys = make([]string, 0, len(header))
	}

	keys = sorter.keys[:0]
	for k := range header {
		keys = append(keys, k)
	}

	sorter.keys = keys
	sort.Sort(sorter)
	return keys
}

func sortedKeyValuesBy(header http.Header, headerOrder []string) (keys []string) {
	sorter := headerSorterPool.Get().(*headerSorter)
	defer headerSorterPool.Put(sorter)

	if cap(sorter.keys) < len(header) {
		sorter.keys = make([]string, 0, len(header))
	}
	keys = sorter.keys[:0]
	for k := range header {
		keys = append(keys, k)
	}
	sorter.keys = keys
	sorter.order = make(map[string]int)
	for i, v := range headerOrder {
		sorter.order[v] = i
	}
	sort.Sort(sorter)
	return keys
}
