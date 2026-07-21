// Package incident provides safe, bounded incident query views.
package incident

import (
	"encoding/json"
	"errors"
	"sort"
	"time"

	"pulse-agent/internal/contract"
	"pulse-agent/internal/store"
)

const maxPageSize = 100

var (
	// ErrInvalidQuery indicates a query outside safe bounds.
	ErrInvalidQuery = errors.New("invalid incident query")
	// ErrNotFound indicates that no persisted incident matched the requested ID.
	ErrNotFound = errors.New("incident not found")
)

// Filter bounds one consistent incident list snapshot.
type Filter struct {
	State    contract.IncidentState `json:"state,omitempty"`
	From     time.Time              `json:"from,omitempty"`
	To       time.Time              `json:"to,omitempty"`
	PageSize int                    `json:"page_size"`
	Offset   int                    `json:"offset"`
}

// Page is one safe, bounded incident list response.
type Page struct {
	Incidents  []contract.Incident `json:"incidents"`
	NextOffset int                 `json:"next_offset"`
}

// Query reads daemon-owned incident records without exposing their raw inputs.
type Query struct{ state *store.Store }

// NewQuery creates a daemon-side incident query service.
func NewQuery(state *store.Store) (*Query, error) {
	if state == nil {
		return nil, ErrInvalidQuery
	}
	return &Query{state: state}, nil
}

// List returns a deterministic page from one store read transaction.
func (q *Query) List(filter Filter) (Page, error) {
	if q == nil || filter.Offset < 0 || filter.PageSize < 0 || filter.PageSize > maxPageSize || (!filter.From.IsZero() && !filter.To.IsZero() && filter.To.Before(filter.From)) {
		return Page{}, ErrInvalidQuery
	}
	if filter.PageSize == 0 {
		filter.PageSize = 25
	}
	items := make([]contract.Incident, 0)
	err := q.state.View(func(tx *store.Tx) error {
		return tx.ForEach(store.BucketIncidents, func(_ string, document []byte) error {
			var record struct {
				Incident contract.Incident `json:"incident"`
			}
			if err := json.Unmarshal(document, &record); err != nil || record.Incident.Validate() != nil {
				return ErrInvalidQuery
			}
			value := record.Incident
			if (filter.State != "" && value.State != filter.State) || (!filter.From.IsZero() && value.OpenedAt.Before(filter.From)) || (!filter.To.IsZero() && value.OpenedAt.After(filter.To)) {
				return nil
			}
			items = append(items, value)
			return nil
		})
	})
	if err != nil {
		return Page{}, err
	}
	sort.Slice(items, func(i, j int) bool { return items[i].IncidentID < items[j].IncidentID })
	if filter.Offset >= len(items) {
		return Page{Incidents: []contract.Incident{}}, nil
	}
	end := filter.Offset + filter.PageSize
	if end > len(items) {
		end = len(items)
	}
	page := Page{Incidents: append([]contract.Incident(nil), items[filter.Offset:end]...)}
	if end < len(items) {
		page.NextOffset = end
	}
	return page, nil
}

// Show returns one safe incident view by immutable incident ID.
func (q *Query) Show(id string) (contract.Incident, error) {
	if q == nil || id == "" {
		return contract.Incident{}, ErrInvalidQuery
	}
	var result contract.Incident
	found := false
	err := q.state.View(func(tx *store.Tx) error {
		return tx.ForEach(store.BucketIncidents, func(_ string, document []byte) error {
			var record struct {
				Incident contract.Incident `json:"incident"`
			}
			if err := json.Unmarshal(document, &record); err != nil || record.Incident.Validate() != nil {
				return ErrInvalidQuery
			}
			if record.Incident.IncidentID == id {
				result, found = record.Incident, true
			}
			return nil
		})
	})
	if err != nil {
		return contract.Incident{}, err
	}
	if !found {
		return contract.Incident{}, ErrNotFound
	}
	return result, nil
}
