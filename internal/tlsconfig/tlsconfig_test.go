package tlsconfig

import (
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newTLSServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	srv.TLS = Server()
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func clientWith(srv *httptest.Server, cfg func(*tls.Config)) *http.Client {
	c := srv.Client()
	tr := c.Transport.(*http.Transport)
	cfg(tr.TLSClientConfig)
	return c
}

func TestRejectsTLS11(t *testing.T) {
	srv := newTLSServer(t)
	c := clientWith(srv, func(c *tls.Config) {
		c.MinVersion = tls.VersionTLS10
		c.MaxVersion = tls.VersionTLS11
	})
	if _, err := c.Get(srv.URL); err == nil {
		t.Fatal("TLS 1.1 handshake succeeded; server must require TLS 1.2+")
	}
}

func TestRejectsNonAEADCipherOnTLS12(t *testing.T) {
	srv := newTLSServer(t)
	c := clientWith(srv, func(c *tls.Config) {
		c.MaxVersion = tls.VersionTLS12
		c.CipherSuites = []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA} // CBC, not approved here
	})
	if _, err := c.Get(srv.URL); err == nil {
		t.Fatal("CBC cipher suite was negotiated; only AES-GCM suites are allowed")
	}
}

func TestAcceptsTLS12WithAESGCM(t *testing.T) {
	srv := newTLSServer(t)
	c := clientWith(srv, func(c *tls.Config) {
		c.MaxVersion = tls.VersionTLS12
		c.CipherSuites = []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}
	})
	resp, err := c.Get(srv.URL)
	if err != nil {
		t.Fatalf("TLS 1.2 + AES-GCM should succeed: %v", err)
	}
	resp.Body.Close()
}

func TestAcceptsTLS13(t *testing.T) {
	srv := newTLSServer(t)
	resp, err := srv.Client().Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.TLS.Version != tls.VersionTLS13 {
		t.Fatalf("expected TLS 1.3, got %x", resp.TLS.Version)
	}
}

func TestAssertFIPS(t *testing.T) {
	if err := assertFIPS(true, false); !errors.Is(err, ErrFIPSRequired) {
		t.Fatalf("FIPS required but disabled must fail startup, got %v", err)
	}
	if err := assertFIPS(true, true); err != nil {
		t.Fatalf("FIPS required and enabled should pass, got %v", err)
	}
	if err := assertFIPS(false, false); err != nil {
		t.Fatalf("FIPS not required should pass, got %v", err)
	}
}
