// Package store is a small in-memory, concurrency-safe store for backup
// retention policies. It stands in for a real database.
package store

import (
	"errors"
	"sync"
)

// ErrNotFound is returned when a policy does not exist.
var ErrNotFound = errors.New("store: policy not found")

// Policy is a backup retention policy.
type Policy struct {
	ID            string `json:"id"`
	RetentionDays int    `json:"retention_days"`
	Immutable     bool   `json:"immutable"`
}

// Store holds policies.
type Store struct {
	mu       sync.RWMutex
	policies map[string]Policy
}

// New returns a store seeded with the given policies.
func New(seed ...Policy) *Store {
	s := &Store{policies: make(map[string]Policy)}
	for _, p := range seed {
		s.policies[p.ID] = p
	}
	return s
}

// Get returns a policy by ID.
func (s *Store) Get(id string) (Policy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.policies[id]
	if !ok {
		return Policy{}, ErrNotFound
	}
	return p, nil
}

// Update replaces a policy and returns the previous version. Returning the
// old value from inside the lock lets callers audit an accurate before/after
// pair even under concurrent writes.
func (s *Store) Update(p Policy) (before Policy, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	before, ok := s.policies[p.ID]
	if !ok {
		return Policy{}, ErrNotFound
	}
	s.policies[p.ID] = p
	return before, nil
}
