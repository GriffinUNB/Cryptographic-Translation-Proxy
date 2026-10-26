#!/bin/bash
# Interop demo: 9-cell signer x verifier verification matrix using patched qpki.
#   C-CA = classical-only (QPKI_VERIFY_FORCE=classical), P-CA = PQC-only (QPKI_VERIFY_FORCE=pqc),
#   CTP  = hybrid (auto). Uses interop/bin/qpki when present.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
Q="$REPO/hsm/qpki"
[ -x "$REPO/interop/bin/qpki" ] && Q="$REPO/interop/bin/qpki"
export PATH="$(dirname "$Q"):$PATH"
PROF="$REPO/interop/profiles"
WORK="$REPO/interop/work"
OUT="$REPO/interop/results/results.txt"

CRED_C="credentials/c-ca"
CRED_P="credentials/p-ca"
CRED_CTP="credentials/ctp"
ROOT_CN="Root CA"

rm -rf "$WORK"; mkdir -p "$WORK"
mkdir -p "$(dirname "$OUT")"; : > "$OUT"

for prof in \
  ec/root-ca \
  ec/tls-client-l3 \
  ec/issuing-ca \
  ml/root-ca-l3 \
  ml/tls-client \
  ml/issuing-ca \
  hybrid/catalyst/root-ca-l3 \
  hybrid/catalyst/tls-client; do
  mkdir -p "$PROF/$(dirname "$prof")"
  cp "$REPO/hsm/profiles/$prof.yaml" "$PROF/$prof.yaml"
done

quiet() { "$@" >/dev/null 2>&1; }

header() {
  printf '\033[33m%s\033[0m\n' "$*"
  printf '%s\n' "$*" >> "$OUT"
}

run() {
  printf '\033[34m$ %s\033[0m\n' "$1"
  printf '$ %s\n' "$1" >> "$OUT"
  local raw
  raw=$(bash -c "$1" 2>&1)
  printf '%s\n' "$raw"
  printf '%s\n' "$raw" | sed 's/\x1b\[[0-9;]*m//g' >> "$OUT"
}

bl() { echo; echo >> "$OUT"; }

# generate CAs, clients, CTP (silent)
cd "$WORK"
mkdir -p "$CRED_C" "$CRED_P" "$CRED_CTP"

quiet qpki ca init \
  --ca-dir c-ca-root \
  --passphrase pw \
  --profile ec/root-ca \
  --var cn="$ROOT_CN"

quiet qpki ca init \
  --ca-dir p-ca-root \
  --passphrase pw \
  --profile ml/root-ca-l3 \
  --var cn="$ROOT_CN"

quiet qpki ca export --ca-dir c-ca-root --out "$CRED_C/c-ca.crt"

quiet qpki ca export --ca-dir p-ca-root --out "$CRED_P/p-ca.crt"

quiet qpki csr gen \
  --algorithm ecdsa-p384 \
  --cn client.c \
  --keyout "$CRED_C/c-key.crt" \
  --key-passphrase kp \
  --out "$CRED_C/c-request.csr"

quiet qpki cert issue \
  --ca-dir c-ca-root \
  --ca-passphrase pw \
  --csr "$CRED_C/c-request.csr" \
  --out "$CRED_C/c-client.crt" \
  --profile "$PROF/ec/tls-client-l3.yaml" \
  --var cn=client.c

quiet qpki csr gen \
  --algorithm ml-dsa-65 \
  --cn client.p \
  --keyout "$CRED_P/p-key.crt" \
  --key-passphrase kp \
  --out "$CRED_P/p-request.csr"

quiet qpki cert issue \
  --ca-dir p-ca-root \
  --ca-passphrase pw \
  --csr "$CRED_P/p-request.csr" \
  --out "$CRED_P/p-client.crt" \
  --profile "$PROF/ml/tls-client.yaml" \
  --var cn=client.p

quiet qpki ca init \
  --ca-dir ctp-root \
  --passphrase pw \
  --profile hybrid/catalyst/root-ca-l3 \
  --var cn="CTP (Hybrid)"

quiet qpki ca export --ca-dir ctp-root --out "$CRED_CTP/ctp-ca.crt"

quiet qpki csr gen \
  --cn "CTP (Hybrid)" \
  --country US \
  --key ctp-root/versions/v1/keys/ca.ecdsa-p384.key \
  --org "ACME Corp" \
  --out "$CRED_CTP/ctp-cross-c.csr" \
  --passphrase pw

quiet qpki cert issue \
  --ca-dir c-ca-root \
  --ca-passphrase pw \
  --csr "$CRED_CTP/ctp-cross-c.csr" \
  --out "$CRED_CTP/ctp-cross-c.crt" \
  --profile "$PROF/ec/issuing-ca.yaml" \
  --var cn="CTP (Hybrid)"

quiet qpki csr gen \
  --cn "CTP (Hybrid)" \
  --country US \
  --key ctp-root/versions/v1/keys/ca.ml-dsa-65.key \
  --org "ACME Corp" \
  --out "$CRED_CTP/ctp-cross-p.csr" \
  --passphrase pw

quiet qpki cert issue \
  --ca-dir p-ca-root \
  --ca-passphrase pw \
  --csr "$CRED_CTP/ctp-cross-p.csr" \
  --out "$CRED_CTP/ctp-cross-p.crt" \
  --profile "$PROF/ml/issuing-ca.yaml" \
  --var cn="CTP (Hybrid)"

quiet qpki csr gen \
  --algorithm ecdsa-p384 \
  --cn client.ctp \
  --hybrid ml-dsa-65 \
  --hybrid-keyout "$CRED_CTP/ctp-ml.crt" \
  --hybrid-passphrase kp \
  --keyout "$CRED_CTP/ctp-ec.crt" \
  --key-passphrase kp \
  --out "$CRED_CTP/ctp-request.csr"

quiet qpki cert issue \
  --ca-dir ctp-root \
  --ca-passphrase pw \
  --csr "$CRED_CTP/ctp-request.csr" \
  --out "$CRED_CTP/ctp-client.crt" \
  --profile "$PROF/hybrid/catalyst/tls-client.yaml" \
  --var cn=client.ctp

# 9-cell matrix
header "# C-CA signer, C-CA verifier"
run "QPKI_VERIFY_FORCE=classical qpki cert verify $CRED_C/c-client.crt --ca $CRED_C/c-ca.crt"

bl
header "# P-CA signer, C-CA verifier"
run "QPKI_VERIFY_FORCE=classical qpki cert verify $CRED_P/p-client.crt --ca $CRED_P/p-ca.crt"

bl
header "# CTP signer, C-CA verifier"
run "QPKI_VERIFY_FORCE=classical qpki cert verify $CRED_CTP/ctp-client.crt --ca $CRED_CTP/ctp-ca.crt"

bl
header "# C-CA signer, P-CA verifier"
run "QPKI_VERIFY_FORCE=pqc qpki cert verify $CRED_C/c-client.crt --ca $CRED_C/c-ca.crt"

bl
header "# P-CA signer, P-CA verifier"
run "QPKI_VERIFY_FORCE=pqc qpki cert verify $CRED_P/p-client.crt --ca $CRED_P/p-ca.crt"

bl
header "# CTP signer, P-CA verifier"
run "QPKI_VERIFY_FORCE=pqc qpki cert verify $CRED_CTP/ctp-client.crt --ca $CRED_CTP/ctp-ca.crt"

bl
header "# C-CA signer, CTP verifier"
run "qpki cert verify $CRED_C/c-client.crt --ca $CRED_C/c-ca.crt"

bl
header "# P-CA signer, CTP verifier"
run "qpki cert verify $CRED_P/p-client.crt --ca $CRED_P/p-ca.crt"

bl
header "# CTP signer, CTP verifier"
run "qpki cert verify $CRED_CTP/ctp-client.crt --ca $CRED_CTP/ctp-ca.crt"
