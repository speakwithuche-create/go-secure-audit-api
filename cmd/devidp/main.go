// Command devidp is a throwaway local identity provider for development.
// It serves a JWKS at http://localhost:9000/jwks.json and prints signed
// tokens you can use with curl. Never use it outside your machine.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	issuer   = "https://dev-idp.local"
	audience = "api://secure-audit-api"
	kid      = "dev-key-1"
)

func main() {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}

	mint := func(sub, scopes string) string {
		now := time.Now()
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"iss": issuer, "aud": audience, "sub": sub, "scp": scopes,
			"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(time.Hour).Unix(),
		})
		tok.Header["kid"] = kid
		s, err := tok.SignedString(key)
		if err != nil {
			log.Fatal(err)
		}
		return s
	}

	fmt.Println("# Tokens valid for 1 hour. Export them in another terminal:")
	fmt.Printf("export ADMIN_TOKEN=%s\n", mint("alice@example.com", "policies.read policies.write"))
	fmt.Printf("export READER_TOKEN=%s\n\n", mint("bob@example.com", "policies.read"))
	fmt.Println("# JWKS served at http://localhost:9000/jwks.json")

	http.HandleFunc("/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid,
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}})
	})
	srv := &http.Server{Addr: "127.0.0.1:9000", ReadHeaderTimeout: 5 * time.Second}
	log.Fatal(srv.ListenAndServe())
}
