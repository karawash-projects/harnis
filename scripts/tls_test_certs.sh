#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
#
# Test-only certificates for tests/test_pg_tls.py: a CA, a server certificate
# for `localhost` signed by it, and a second, unrelated CA. Extensions follow
# what strict X.509 checking (Python 3.13+) requires. Never use these anywhere
# real.
#
#   scripts/tls_test_certs.sh <out-dir>
set -euo pipefail
out=${1:?usage: tls_test_certs.sh <out-dir>}
mkdir -p "$out" && cd "$out"
cat > ca.ext <<'EXT'
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
EXT
cat > server.ext <<'EXT'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
EXT
for name in ca other-ca; do
  openssl req -new -newkey rsa:2048 -nodes -subj "/CN=Harnis test $name" -keyout "$name.key" -out "$name.csr" 2>/dev/null
  openssl x509 -req -in "$name.csr" -signkey "$name.key" -days 7 -extfile ca.ext -out "$name.crt" 2>/dev/null
done
openssl req -new -newkey rsa:2048 -nodes -subj "/CN=localhost" -keyout server.key -out server.csr 2>/dev/null
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 7 -extfile server.ext \
  -out server.crt 2>/dev/null
openssl verify -x509_strict -CAfile ca.crt server.crt
