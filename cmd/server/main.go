// Command server runs the secure audit API.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/speakwithuche-create/go-secure-audit-api/internal/api"
	"github.com/speakwithuche-create/go-secure-audit-api/internal/audit"
	"github.com/speakwithuche-create/go-secure-audit-api/internal/auth"
	"github.com/speakwithuche-create/go-secure-audit-api/internal/store"
	"github.com/speakwithuche-create/go-secure-audit-api/internal/tlsconfig"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := run(log); err != nil {
		log.Error("server stopped", "error", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	cfg := struct {
		Addr, JWKSURL, Issuer, Audience, CertFile, KeyFile string
		RequireFIPS, AllowHTTP                             bool
	}{
		Addr:        env("ADDR", ":8443"),
		JWKSURL:     os.Getenv("JWKS_URL"),
		Issuer:      os.Getenv("TOKEN_ISSUER"),
		Audience:    os.Getenv("TOKEN_AUDIENCE"),
		CertFile:    os.Getenv("TLS_CERT_FILE"),
		KeyFile:     os.Getenv("TLS_KEY_FILE"),
		RequireFIPS: os.Getenv("REQUIRE_FIPS") == "true",
		AllowHTTP:   os.Getenv("ALLOW_INSECURE_HTTP") == "true",
	}

	// Startup assertions: refuse to run in a non-compliant configuration.
	if err := tlsconfig.AssertFIPS(cfg.RequireFIPS); err != nil {
		return err
	}
	if cfg.JWKSURL == "" || cfg.Issuer == "" || cfg.Audience == "" {
		return errors.New("JWKS_URL, TOKEN_ISSUER and TOKEN_AUDIENCE are required")
	}
	if (cfg.CertFile == "" || cfg.KeyFile == "") && !cfg.AllowHTTP {
		return errors.New("TLS_CERT_FILE and TLS_KEY_FILE are required (set ALLOW_INSECURE_HTTP=true for local development only)")
	}

	srv := &api.Server{
		Tokens: &auth.Validator{
			Keys:     auth.NewKeySet(cfg.JWKSURL, nil),
			Issuer:   cfg.Issuer,
			Audience: cfg.Audience,
			Leeway:   30 * time.Second,
		},
		Store: store.New(
			store.Policy{ID: "daily", RetentionDays: 30, Immutable: true},
			store.Policy{ID: "monthly", RetentionDays: 365, Immutable: true},
		),
		Audit: audit.NewJSONSink(os.Stdout), // audit on stdout, app logs on stderr
		Log:   log,
	}

	httpSrv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           srv.Handler(),
		TLSConfig:         tlsconfig.Server(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errCh := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", cfg.Addr, "tls", !cfg.AllowHTTP, "fips_required", cfg.RequireFIPS)
		if cfg.AllowHTTP && cfg.CertFile == "" {
			errCh <- httpSrv.ListenAndServe()
		} else {
			errCh <- httpSrv.ListenAndServeTLS(cfg.CertFile, cfg.KeyFile)
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return httpSrv.Shutdown(shutdownCtx)
	}
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
