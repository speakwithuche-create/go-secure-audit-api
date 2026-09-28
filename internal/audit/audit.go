// Package audit emits structured audit events for privileged operations.
//
// Every event answers: who (actor) did what (action) to which resource
// (target), what it looked like before and after, whether it worked
// (outcome), and which request it belongs to (correlation ID). Events are
// written as one JSON object per line so any log pipeline (Fluent Bit,
// OpenTelemetry Collector, a SIEM) can ingest them without custom parsing.
package audit

import (
	"encoding/json"
	"io"
	"sync"
	"time"
)

// Outcome of an audited action.
type Outcome string

const (
	Success Outcome = "success"
	Denied  Outcome = "denied"
	Failure Outcome = "failure"
)

// Event is a single audit record.
type Event struct {
	Time          time.Time `json:"time"`
	Type          string    `json:"type"` // always "audit" so pipelines can route it
	Action        string    `json:"action"`
	Actor         string    `json:"actor"`
	Target        string    `json:"target"`
	Before        any       `json:"before,omitempty"`
	After         any       `json:"after,omitempty"`
	Outcome       Outcome   `json:"outcome"`
	Reason        string    `json:"reason,omitempty"`
	CorrelationID string    `json:"correlation_id"`
	SourceIP      string    `json:"source_ip,omitempty"`
}

// Sink receives audit events.
type Sink interface {
	Emit(Event)
}

// JSONSink writes events as JSON lines. It is safe for concurrent use.
type JSONSink struct {
	mu  sync.Mutex
	enc *json.Encoder
	now func() time.Time
}

// NewJSONSink returns a sink that writes to w.
func NewJSONSink(w io.Writer) *JSONSink {
	return &JSONSink{enc: json.NewEncoder(w), now: time.Now}
}

// Emit writes e, stamping the time and type.
func (s *JSONSink) Emit(e Event) {
	e.Type = "audit"
	if e.Time.IsZero() {
		e.Time = s.now().UTC()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.enc.Encode(e) // audit writes must never crash a request
}

// Recorder keeps events in memory. Use it in tests.
type Recorder struct {
	mu     sync.Mutex
	Events []Event
}

// Emit stores e.
func (r *Recorder) Emit(e Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e.Type = "audit"
	r.Events = append(r.Events, e)
}

// All returns a copy of the recorded events.
func (r *Recorder) All() []Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Event(nil), r.Events...)
}
