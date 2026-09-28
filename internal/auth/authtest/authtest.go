// Package authtest provides a fake identity provider for tests: an RSA
// signing key, a JWKS endpoint that publishes it, and a token minter.
package authtest

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	Issuer   = "https://login.example.test/tenant/v2.0"
	Audience = "api://secure-audit-api"
	KeyID    = "test-key-1"
)

// IdP is a fake identity provider.
type IdP struct {
	Key     *rsa.PrivateKey
	Server  *httptest.Server
	Fetches atomic.Int32
}

// New starts a JWKS server publishing a fresh 2048-bit key.
func New(t *testing.T) *IdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	idp := &IdP{Key: key}
	idp.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		idp.Fetches.Add(1)
		pub := key.PublicKey
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "use": "sig", "alg": "RS256", "kid": KeyID,
			"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}}})
	}))
	t.Cleanup(idp.Server.Close)
	return idp
}

// URL is the JWKS endpoint.
func (i *IdP) URL() string { return i.Server.URL }

// Claims returns valid default claims for subject sub with the given scopes.
func Claims(sub, scopes string) jwt.MapClaims {
	now := time.Now()
	return jwt.MapClaims{
		"iss": Issuer,
		"aud": Audience,
		"sub": sub,
		"scp": scopes,
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"exp": now.Add(10 * time.Minute).Unix(),
	}
}

// Sign signs claims with RS256 and the IdP's key.
func (i *IdP) Sign(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = KeyID
	s, err := tok.SignedString(i.Key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
