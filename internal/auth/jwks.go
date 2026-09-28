// Package auth validates OAuth 2.0 / OIDC bearer tokens (JWTs) statelessly
// using public keys published at the identity provider's JWKS endpoint.
package auth

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"
)

// ErrUnknownKey is returned when a token's "kid" is not in the key set,
// even after a refresh.
var ErrUnknownKey = errors.New("auth: signing key not found in JWKS")

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type jwkSet struct {
	Keys []jwk `json:"keys"`
}

// KeySet fetches and caches RSA signing keys from a JWKS URL.
//
// Keys are cached for TTL. When a token references an unknown key ID the set
// is refreshed once (identity providers rotate keys by publishing the new key
// before they start signing with it), but refreshes are rate limited by
// MinRefreshInterval so an attacker cannot use random "kid" values to make us
// hammer the identity provider.
type KeySet struct {
	URL                string
	Client             *http.Client
	TTL                time.Duration
	MinRefreshInterval time.Duration

	mu          sync.RWMutex
	keys        map[string]*rsa.PublicKey
	fetchedAt   time.Time
	lastAttempt time.Time
}

// NewKeySet returns a KeySet with safe defaults.
func NewKeySet(url string, client *http.Client) *KeySet {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &KeySet{
		URL:                url,
		Client:             client,
		TTL:                15 * time.Minute,
		MinRefreshInterval: 30 * time.Second,
	}
}

// Key returns the public key for kid, refreshing the cache if needed.
func (k *KeySet) Key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	k.mu.RLock()
	key, ok := k.keys[kid]
	fresh := time.Since(k.fetchedAt) < k.TTL
	k.mu.RUnlock()
	if ok && fresh {
		return key, nil
	}

	if err := k.refresh(ctx); err != nil {
		// Fall back to a cached key if the IdP is briefly unreachable.
		if ok {
			return key, nil
		}
		return nil, err
	}

	k.mu.RLock()
	defer k.mu.RUnlock()
	if key, ok := k.keys[kid]; ok {
		return key, nil
	}
	return nil, ErrUnknownKey
}

func (k *KeySet) refresh(ctx context.Context) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if !k.lastAttempt.IsZero() && time.Since(k.lastAttempt) < k.MinRefreshInterval {
		return nil // rate limited; caller uses whatever is cached
	}
	k.lastAttempt = time.Now()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, k.URL, nil)
	if err != nil {
		return err
	}
	resp, err := k.Client.Do(req)
	if err != nil {
		return fmt.Errorf("auth: fetch JWKS: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("auth: fetch JWKS: unexpected status %d", resp.StatusCode)
	}

	var set jwkSet
	if err := json.NewDecoder(http.MaxBytesReader(nil, resp.Body, 1<<20)).Decode(&set); err != nil {
		return fmt.Errorf("auth: decode JWKS: %w", err)
	}

	keys := make(map[string]*rsa.PublicKey, len(set.Keys))
	for _, j := range set.Keys {
		if j.Kty != "RSA" || (j.Use != "" && j.Use != "sig") {
			continue
		}
		pub, err := j.rsaPublicKey()
		if err != nil {
			continue // skip malformed keys rather than failing the whole set
		}
		keys[j.Kid] = pub
	}
	k.keys = keys
	k.fetchedAt = time.Now()
	return nil
}

func (j jwk) rsaPublicKey() (*rsa.PublicKey, error) {
	nb, err := base64.RawURLEncoding.DecodeString(j.N)
	if err != nil {
		return nil, err
	}
	eb, err := base64.RawURLEncoding.DecodeString(j.E)
	if err != nil {
		return nil, err
	}
	e := new(big.Int).SetBytes(eb)
	if !e.IsInt64() || e.Int64() < 3 {
		return nil, errors.New("auth: invalid RSA exponent")
	}
	pub := &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: int(e.Int64())}
	if pub.N.BitLen() < 2048 {
		return nil, errors.New("auth: RSA key shorter than 2048 bits")
	}
	return pub, nil
}
