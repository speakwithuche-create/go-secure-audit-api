package auth

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Claims are the token claims this service relies on.
type Claims struct {
	Scope string `json:"scp,omitempty"` // space-separated scopes (Entra ID uses "scp")
	jwt.RegisteredClaims
}

// HasScope reports whether the token grants scope s.
func (c *Claims) HasScope(s string) bool {
	return slices.Contains(strings.Fields(c.Scope), s)
}

// Validator checks bearer tokens against a JWKS, an expected issuer and an
// expected audience.
type Validator struct {
	Keys     *KeySet
	Issuer   string
	Audience string
	Leeway   time.Duration
}

// Validate parses and verifies a raw JWT. Only RS256 is accepted: pinning the
// algorithm blocks "alg: none" tokens and algorithm-confusion attacks where an
// attacker signs with HS256 using the public key as an HMAC secret.
func (v *Validator) Validate(ctx context.Context, raw string) (*Claims, error) {
	claims := &Claims{}
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer(v.Issuer),
		jwt.WithAudience(v.Audience),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(v.Leeway),
	)
	_, err := parser.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("token has no kid header")
		}
		return v.Keys.Key(ctx, kid)
	})
	if err != nil {
		return nil, fmt.Errorf("auth: invalid token: %w", err)
	}
	if claims.Subject == "" {
		return nil, errors.New("auth: token has no subject")
	}
	return claims, nil
}
