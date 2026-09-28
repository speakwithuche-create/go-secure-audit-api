package auth_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/speakwithuche-create/go-secure-audit-api/internal/auth"
	"github.com/speakwithuche-create/go-secure-audit-api/internal/auth/authtest"
)

func newValidator(idp *authtest.IdP) *auth.Validator {
	return &auth.Validator{
		Keys:     auth.NewKeySet(idp.URL(), nil),
		Issuer:   authtest.Issuer,
		Audience: authtest.Audience,
	}
}

func TestValidTokenIsAccepted(t *testing.T) {
	idp := authtest.New(t)
	v := newValidator(idp)

	claims, err := v.Validate(context.Background(), idp.Sign(t, authtest.Claims("alice", "policies.read policies.write")))
	if err != nil {
		t.Fatalf("expected valid token, got %v", err)
	}
	if claims.Subject != "alice" || !claims.HasScope("policies.write") {
		t.Fatalf("unexpected claims: %+v", claims)
	}
}

// Each case asserts a security behavior: a token that must be rejected.
func TestInvalidTokensAreRejected(t *testing.T) {
	idp := authtest.New(t)
	v := newValidator(idp)

	mutate := func(f func(jwt.MapClaims)) string {
		c := authtest.Claims("alice", "policies.write")
		f(c)
		return idp.Sign(t, c)
	}

	otherKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	signedByAttacker := func() string {
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, authtest.Claims("mallory", "policies.write"))
		tok.Header["kid"] = authtest.KeyID
		s, _ := tok.SignedString(otherKey)
		return s
	}

	// Algorithm confusion: HS256 "signed" with the public key as the HMAC secret.
	algConfusion := func() string {
		pubDER, _ := x509.MarshalPKIXPublicKey(&idp.Key.PublicKey)
		tok := jwt.NewWithClaims(jwt.SigningMethodHS256, authtest.Claims("mallory", "policies.write"))
		tok.Header["kid"] = authtest.KeyID
		s, _ := tok.SignedString(pubDER)
		return s
	}

	algNone := func() string {
		tok := jwt.NewWithClaims(jwt.SigningMethodNone, authtest.Claims("mallory", "policies.write"))
		tok.Header["kid"] = authtest.KeyID
		s, _ := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
		return s
	}

	unknownKid := func() string {
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, authtest.Claims("alice", "policies.write"))
		tok.Header["kid"] = "not-a-real-key"
		s, _ := tok.SignedString(idp.Key)
		return s
	}

	cases := map[string]string{
		"expired":             mutate(func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-time.Hour).Unix() }),
		"no expiry":           mutate(func(c jwt.MapClaims) { delete(c, "exp") }),
		"not yet valid":       mutate(func(c jwt.MapClaims) { c["nbf"] = time.Now().Add(time.Hour).Unix() }),
		"wrong issuer":        mutate(func(c jwt.MapClaims) { c["iss"] = "https://evil.example" }),
		"wrong audience":      mutate(func(c jwt.MapClaims) { c["aud"] = "api://some-other-api" }),
		"no subject":          mutate(func(c jwt.MapClaims) { delete(c, "sub") }),
		"signed by other key": signedByAttacker(),
		"alg confusion HS256": algConfusion(),
		"alg none":            algNone(),
		"unknown kid":         unknownKid(),
		"garbage":             "not.a.jwt",
		"tampered payload":    idp.Sign(t, authtest.Claims("alice", "policies.read")) + "x",
	}

	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := v.Validate(context.Background(), raw); err == nil {
				t.Fatalf("token %q was accepted; it must be rejected", name)
			}
		})
	}
}

func TestKeysAreCachedNotFetchedPerRequest(t *testing.T) {
	idp := authtest.New(t)
	v := newValidator(idp)
	tok := idp.Sign(t, authtest.Claims("alice", ""))

	for range 20 {
		if _, err := v.Validate(context.Background(), tok); err != nil {
			t.Fatal(err)
		}
	}
	if idp.Fetches.Load() != 1 {
		t.Fatalf("expected 1 JWKS fetch, got %d", idp.Fetches.Load())
	}
}

func TestUnknownKidRefreshIsRateLimited(t *testing.T) {
	idp := authtest.New(t)
	v := newValidator(idp)

	for range 10 {
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, authtest.Claims("mallory", ""))
		tok.Header["kid"] = "random-kid"
		s, _ := tok.SignedString(idp.Key)
		_, _ = v.Validate(context.Background(), s)
	}
	if idp.Fetches.Load() > 1 {
		t.Fatalf("unknown kids triggered %d JWKS fetches; refresh must be rate limited", idp.Fetches.Load())
	}
}
