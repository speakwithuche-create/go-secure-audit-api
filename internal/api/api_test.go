package api_test

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/speakwithuche-create/go-secure-audit-api/internal/api"
	"github.com/speakwithuche-create/go-secure-audit-api/internal/audit"
	"github.com/speakwithuche-create/go-secure-audit-api/internal/auth"
	"github.com/speakwithuche-create/go-secure-audit-api/internal/auth/authtest"
	"github.com/speakwithuche-create/go-secure-audit-api/internal/store"
)

type fixture struct {
	idp   *authtest.IdP
	rec   *audit.Recorder
	h     http.Handler
	store *store.Store
}

func setup(t *testing.T) *fixture {
	t.Helper()
	idp := authtest.New(t)
	rec := &audit.Recorder{}
	st := store.New(store.Policy{ID: "daily", RetentionDays: 30, Immutable: true})
	srv := &api.Server{
		Tokens: &auth.Validator{Keys: auth.NewKeySet(idp.URL(), nil), Issuer: authtest.Issuer, Audience: authtest.Audience},
		Store:  st,
		Audit:  rec,
		Log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	return &fixture{idp: idp, rec: rec, h: srv.Handler(), store: st}
}

func (f *fixture) do(t *testing.T, method, path, token, body string, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	f.h.ServeHTTP(w, req)
	return w
}

func TestMissingTokenIs401AndNoAuditEvent(t *testing.T) {
	f := setup(t)
	w := f.do(t, "PUT", "/v1/policies/daily", "", `{"retention_days":1}`, nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", w.Code)
	}
	if p, _ := f.store.Get("daily"); p.RetentionDays != 30 {
		t.Fatal("unauthenticated request changed data")
	}
	if n := len(f.rec.All()); n != 0 {
		t.Fatalf("want no audit event for anonymous request, got %d", n)
	}
}

func TestMissingScopeIs403AndAuditedAsDenied(t *testing.T) {
	f := setup(t)
	tok := f.idp.Sign(t, authtest.Claims("bob", "policies.read"))
	w := f.do(t, "PUT", "/v1/policies/daily", tok, `{"retention_days":1}`, map[string]string{api.CorrelationHeader: "req-123"})

	if w.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d", w.Code)
	}
	ev := f.rec.All()
	if len(ev) != 1 {
		t.Fatalf("want 1 audit event, got %d", len(ev))
	}
	e := ev[0]
	if e.Outcome != audit.Denied || e.Actor != "bob" || e.Target != "policy/daily" || e.CorrelationID != "req-123" {
		t.Fatalf("unexpected denied event: %+v", e)
	}
	if p, _ := f.store.Get("daily"); p.RetentionDays != 30 {
		t.Fatal("forbidden request changed data")
	}
}

func TestPrivilegedUpdateEmitsCompleteAuditEvent(t *testing.T) {
	f := setup(t)
	tok := f.idp.Sign(t, authtest.Claims("alice", "policies.write"))
	w := f.do(t, "PUT", "/v1/policies/daily", tok, `{"retention_days":90,"immutable":true}`,
		map[string]string{api.CorrelationHeader: "trace-abc"})

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body)
	}
	if w.Header().Get(api.CorrelationHeader) != "trace-abc" {
		t.Fatal("correlation ID must be echoed on the response")
	}

	ev := f.rec.All()
	if len(ev) != 1 {
		t.Fatalf("want 1 audit event, got %d", len(ev))
	}
	e := ev[0]
	before, _ := e.Before.(store.Policy)
	after, _ := e.After.(store.Policy)
	switch {
	case e.Type != "audit", e.Action != "policy.update", e.Outcome != audit.Success:
		t.Fatalf("bad event header: %+v", e)
	case e.Actor != "alice", e.Target != "policy/daily", e.CorrelationID != "trace-abc":
		t.Fatalf("bad who/what/correlation: %+v", e)
	case before.RetentionDays != 30 || after.RetentionDays != 90:
		t.Fatalf("before/after state wrong: before=%+v after=%+v", before, after)
	}
}

func TestInvalidInputIsAuditedAsFailure(t *testing.T) {
	f := setup(t)
	tok := f.idp.Sign(t, authtest.Claims("alice", "policies.write"))
	for _, body := range []string{`{"retention_days":0}`, `{"retention_days":30,"admin":true}`, `not json`} {
		w := f.do(t, "PUT", "/v1/policies/daily", tok, body, nil)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("body %q: want 400, got %d", body, w.Code)
		}
	}
	for _, e := range f.rec.All() {
		if e.Outcome != audit.Failure {
			t.Fatalf("want failure outcome, got %+v", e)
		}
	}
	if n := len(f.rec.All()); n != 3 {
		t.Fatalf("want 3 failure events, got %d", n)
	}
}

func TestHostileCorrelationIDIsReplaced(t *testing.T) {
	f := setup(t)
	w := f.do(t, "GET", "/healthz", "", "", map[string]string{api.CorrelationHeader: "bad\nvalue with spaces"})
	got := w.Header().Get(api.CorrelationHeader)
	if got == "" || strings.ContainsAny(got, "\n ") {
		t.Fatalf("hostile correlation ID was not replaced: %q", got)
	}
}

func TestSecurityHeadersPresent(t *testing.T) {
	f := setup(t)
	w := f.do(t, "GET", "/healthz", "", "", nil)
	for _, h := range []string{"Strict-Transport-Security", "X-Content-Type-Options", "Cache-Control"} {
		if w.Header().Get(h) == "" {
			t.Errorf("missing header %s", h)
		}
	}
}

// Run with -race: concurrent writers must each produce exactly one audit
// event whose "before" matches a real prior state.
func TestConcurrentUpdatesAreAllAudited(t *testing.T) {
	f := setup(t)
	tok := f.idp.Sign(t, authtest.Claims("alice", "policies.write"))

	const n = 50
	var wg sync.WaitGroup
	for i := 1; i <= n; i++ {
		wg.Add(1)
		go func(days int) {
			defer wg.Done()
			f.do(t, "PUT", "/v1/policies/daily", tok, fmt.Sprintf(`{"retention_days":%d}`, 100+days), nil)
		}(i)
	}
	wg.Wait()

	events := f.rec.All()
	if len(events) != n {
		t.Fatalf("want %d audit events, got %d", n, len(events))
	}
	// Every "after" except the final one must appear as exactly one "before".
	befores := map[int]int{}
	for _, e := range events {
		befores[e.Before.(store.Policy).RetentionDays]++
	}
	for days, count := range befores {
		if count != 1 {
			t.Fatalf("state %d appeared as 'before' %d times; audit trail is inconsistent", days, count)
		}
	}
}

func TestAuditSinkWritesJSONLines(t *testing.T) {
	var buf strings.Builder
	sink := audit.NewJSONSink(&buf)
	sink.Emit(audit.Event{Action: "policy.update", Actor: "alice", Target: "policy/daily", Outcome: audit.Success, CorrelationID: "c1"})

	var got map[string]any
	if err := json.Unmarshal([]byte(buf.String()), &got); err != nil {
		t.Fatalf("audit output is not JSON: %v", err)
	}
	for _, k := range []string{"time", "type", "action", "actor", "target", "outcome", "correlation_id"} {
		if _, ok := got[k]; !ok {
			t.Errorf("audit event missing field %q", k)
		}
	}
}
