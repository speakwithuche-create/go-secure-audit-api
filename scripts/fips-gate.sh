#!/usr/bin/env bash
# CI gate: proves the FIPS startup assertion works in both directions.
#  1. A binary built WITHOUT the FIPS module must refuse to start when REQUIRE_FIPS=true.
#  2. A binary built WITH GOFIPS140=v1.0.0 must pass the same check.
set -euo pipefail
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
common_env=(REQUIRE_FIPS=true JWKS_URL=http://127.0.0.1:1/jwks.json TOKEN_ISSUER=x TOKEN_AUDIENCE=y ALLOW_INSECURE_HTTP=true ADDR=127.0.0.1:0)

go build -o "$tmp/nonfips" ./cmd/server
if env "${common_env[@]}" timeout 3 "$tmp/nonfips" 2>"$tmp/out"; then
  echo "FAIL: non-FIPS binary started with REQUIRE_FIPS=true"; exit 1
fi
grep -q "FIPS 140-3 mode required" "$tmp/out" || { echo "FAIL: wrong error"; cat "$tmp/out"; exit 1; }
echo "ok: non-FIPS binary refused to start"

GOFIPS140=v1.0.0 go build -o "$tmp/fips" ./cmd/server
set +e
env "${common_env[@]}" timeout 3 "$tmp/fips" 2>"$tmp/out"; code=$?
set -e
if grep -q "FIPS 140-3 mode required" "$tmp/out"; then
  echo "FAIL: FIPS binary failed the FIPS assertion"; cat "$tmp/out"; exit 1
fi
[ "$code" = 124 ] || { echo "FAIL: FIPS binary exited early ($code)"; cat "$tmp/out"; exit 1; }
echo "ok: FIPS binary passed the startup assertion and began serving"
