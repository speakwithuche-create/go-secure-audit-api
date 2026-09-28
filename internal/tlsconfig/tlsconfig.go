// Package tlsconfig builds the server TLS configuration and the startup
// checks that go with it.
package tlsconfig

import (
	"crypto/fips140"
	"crypto/tls"
	"errors"
)

// Server returns a TLS configuration limited to TLS 1.2+ with ECDHE key
// exchange and AES-GCM cipher suites, all of which are FIPS 140-approved.
// TLS 1.3 suites are not configurable in Go and are all AES-GCM or
// ChaCha20; in FIPS mode Go disables ChaCha20 automatically.
func Server() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		CurvePreferences: []tls.CurveID{tls.CurveP384, tls.CurveP256},
	}
}

// ErrFIPSRequired is returned by AssertFIPS when FIPS mode is required but
// not enabled.
var ErrFIPSRequired = errors.New("tlsconfig: FIPS 140-3 mode required but not enabled " +
	"(build with GOFIPS140=v1.0.0 or run with GODEBUG=fips140=on)")

// AssertFIPS fails when required is true and the Go cryptographic module is
// not running in FIPS 140-3 mode. Call it at startup so a non-compliant
// binary refuses to serve traffic instead of silently running.
func AssertFIPS(required bool) error {
	return assertFIPS(required, fips140.Enabled())
}

func assertFIPS(required, enabled bool) error {
	if required && !enabled {
		return ErrFIPSRequired
	}
	return nil
}
