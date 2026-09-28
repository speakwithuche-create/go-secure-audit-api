.PHONY: test race fips-test fips-gate lint run-idp run build-fips

test:        ## unit tests
	go test ./...
race:        ## tests with the race detector
	go test -race -count=1 ./...
fips-test:   ## tests with the Go FIPS 140-3 module enabled
	GODEBUG=fips140=on go test -count=1 ./...
fips-gate:   ## prove a non-FIPS build cannot start when FIPS is required
	./scripts/fips-gate.sh
lint:
	gofmt -l . | (! grep .) && go vet ./...
run-idp:     ## local fake identity provider + tokens
	go run ./cmd/devidp
run:         ## run the API on http://localhost:8080 against the local IdP
	JWKS_URL=http://127.0.0.1:9000/jwks.json TOKEN_ISSUER=https://dev-idp.local \
	TOKEN_AUDIENCE=api://secure-audit-api ALLOW_INSECURE_HTTP=true ADDR=127.0.0.1:8080 \
	go run ./cmd/server
build-fips:
	CGO_ENABLED=0 GOFIPS140=v1.0.0 go build -trimpath -o bin/server ./cmd/server
