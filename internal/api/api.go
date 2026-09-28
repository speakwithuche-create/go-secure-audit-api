// Package api wires HTTP routes, authentication, authorization and audit
// logging together.
package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"strings"

	"github.com/speakwithuche-create/go-secure-audit-api/internal/audit"
	"github.com/speakwithuche-create/go-secure-audit-api/internal/auth"
	"github.com/speakwithuche-create/go-secure-audit-api/internal/store"
)

// Scope required to change a policy.
const ScopePoliciesWrite = "policies.write"

// Scope required to read a policy.
const ScopePoliciesRead = "policies.read"

// CorrelationHeader carries the request's correlation ID.
const CorrelationHeader = "X-Correlation-ID"

type ctxKey int

const (
	claimsKey ctxKey = iota
	correlationKey
)

// TokenValidator validates bearer tokens.
type TokenValidator interface {
	Validate(ctx context.Context, raw string) (*auth.Claims, error)
}

// Server is the HTTP API.
type Server struct {
	Tokens TokenValidator
	Store  *store.Store
	Audit  audit.Sink
	Log    *slog.Logger
}

// Handler returns the routed, middleware-wrapped handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.Handle("GET /v1/policies/{id}", s.authenticate(s.requireScope(ScopePoliciesRead, "policy.read", http.HandlerFunc(s.getPolicy))))
	mux.Handle("PUT /v1/policies/{id}", s.authenticate(s.requireScope(ScopePoliciesWrite, "policy.update", http.HandlerFunc(s.updatePolicy))))
	return s.correlation(s.securityHeaders(mux))
}

var validCorrelationID = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)

// correlation reuses an incoming correlation ID (so a request can be traced
// across services) or creates one, and echoes it on the response.
func (s *Server) correlation(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(CorrelationHeader)
		if !validCorrelationID.MatchString(id) { // never trust unbounded client input in logs
			id = newID()
		}
		w.Header().Set(CorrelationHeader, id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), correlationKey, id)))
	})
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || raw == "" {
			w.Header().Set("WWW-Authenticate", `Bearer`)
			writeError(w, http.StatusUnauthorized, "missing bearer token")
			return
		}
		claims, err := s.Tokens.Validate(r.Context(), raw)
		if err != nil {
			s.Log.WarnContext(r.Context(), "token rejected",
				"correlation_id", CorrelationID(r.Context()), "error", err)
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
			writeError(w, http.StatusUnauthorized, "invalid token")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), claimsKey, claims)))
	})
}

// requireScope returns 403 and writes a "denied" audit event when the token
// lacks scope. Denials are audited because repeated denied attempts are what
// a security team looks for.
func (s *Server) requireScope(scope, action string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := claimsFrom(r.Context())
		if !c.HasScope(scope) {
			s.Audit.Emit(audit.Event{
				Action:        action,
				Actor:         c.Subject,
				Target:        "policy/" + r.PathValue("id"),
				Outcome:       audit.Denied,
				Reason:        "missing scope " + scope,
				CorrelationID: CorrelationID(r.Context()),
				SourceIP:      clientIP(r),
			})
			writeError(w, http.StatusForbidden, "insufficient scope")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) getPolicy(w http.ResponseWriter, r *http.Request) {
	p, err := s.Store.Get(r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "policy not found")
		return
	}
	writeJSON(w, http.StatusOK, p)
}

type updateRequest struct {
	RetentionDays int  `json:"retention_days"`
	Immutable     bool `json:"immutable"`
}

func (s *Server) updatePolicy(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	c := claimsFrom(r.Context())
	ev := audit.Event{
		Action:        "policy.update",
		Actor:         c.Subject,
		Target:        "policy/" + id,
		CorrelationID: CorrelationID(r.Context()),
		SourceIP:      clientIP(r),
	}

	var req updateRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		ev.Outcome, ev.Reason = audit.Failure, "invalid request body"
		s.Audit.Emit(ev)
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.RetentionDays < 1 || req.RetentionDays > 3650 {
		ev.Outcome, ev.Reason = audit.Failure, "retention_days out of range"
		s.Audit.Emit(ev)
		writeError(w, http.StatusBadRequest, "retention_days must be between 1 and 3650")
		return
	}

	after := store.Policy{ID: id, RetentionDays: req.RetentionDays, Immutable: req.Immutable}
	before, err := s.Store.Update(after)
	if errors.Is(err, store.ErrNotFound) {
		ev.Outcome, ev.Reason = audit.Failure, "policy not found"
		s.Audit.Emit(ev)
		writeError(w, http.StatusNotFound, "policy not found")
		return
	}

	ev.Before, ev.After, ev.Outcome = before, after, audit.Success
	s.Audit.Emit(ev)
	writeJSON(w, http.StatusOK, after)
}

// CorrelationID returns the request's correlation ID.
func CorrelationID(ctx context.Context) string {
	id, _ := ctx.Value(correlationKey).(string)
	return id
}

func claimsFrom(ctx context.Context) *auth.Claims {
	c, _ := ctx.Value(claimsKey).(*auth.Claims)
	if c == nil {
		return &auth.Claims{}
	}
	return c
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
