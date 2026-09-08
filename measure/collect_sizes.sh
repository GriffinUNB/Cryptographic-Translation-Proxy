#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE="$(dirname "$SCRIPT_DIR")"
RD="$SCRIPT_DIR/results"
mkdir -p "$RD"

case "${1:-all}" in
  l1) LEVELS=(l1) ;;
  l3) LEVELS=(l3) ;;
  l5) LEVELS=(l5) ;;
  all) LEVELS=(l1 l3 l5) ;;
  *) echo "Usage: $0 [l1|l3|l5|all]" >&2; exit 1 ;;
esac

for level in "${LEVELS[@]}"; do
  case "$level" in
    l1) C_PROFILE=ec/tls-client;     P_PROFILE=ml/tls-client-l1; P_ALGO=ml-dsa-44; C_ALGO=ecdsa-p256 ;;
    l3) C_PROFILE=ec/tls-client-l3;  P_PROFILE=ml/tls-client;    P_ALGO=ml-dsa-65; C_ALGO=ecdsa-p384 ;;
    l5) C_PROFILE=ec/tls-client-l5;  P_PROFILE=ml/tls-client-l5; P_ALGO=ml-dsa-87; C_ALGO=ecdsa-p521 ;;
  esac

  bash "$BASE/run_level.sh" "$level" up

  docker exec ctp-entity-classical sh -c \
    "qpki key gen -a '$C_ALGO' -o /tmp/pure-classical-key.pem -p temp >/dev/null 2>&1 && qpki csr gen --key /tmp/pure-classical-key.pem --passphrase temp --cn pure-classical-client -o /tmp/pure-classical.csr >/dev/null 2>&1 && qpki cert issue --ca-dir /ca/entity-classical --csr /tmp/pure-classical.csr --profile '/opt/qpki/profiles/$C_PROFILE.yaml' --out /shared/pure-classical-client.crt --var cn=pure-classical-client --ca-passphrase CTPLab2026 >/dev/null 2>&1"
  docker exec ctp-entity-pqc sh -c \
    "qpki key gen -a '$P_ALGO' -o /tmp/pure-pqc-key.pem -p temp >/dev/null 2>&1 && qpki csr gen --key /tmp/pure-pqc-key.pem --passphrase temp --cn pure-pqc-client -o /tmp/pure-pqc.csr >/dev/null 2>&1 && qpki cert issue --ca-dir /ca/entity-pqc --csr /tmp/pure-pqc.csr --profile '/opt/qpki/profiles/$P_PROFILE.yaml' --out /shared/pure-pqc-client.crt --var cn=pure-pqc-client --ca-passphrase CTPLab2026 >/dev/null 2>&1"

  declare -A FILES=(
    [classical-ca]="ctp-entity-classical:/ca/entity-classical/ca.crt"
    [pqc-ca]="ctp-entity-pqc:/ca/entity-pqc/ca.crt"
    [classical-hp-root]="ctp-classical-hp:/shared/classical-hp-self-signed.crt"
    [pqc-hp-root]="ctp-pqc-hp:/shared/pqc-hp-self-signed.crt"
    [classical-hp-cross]="ctp-entity-classical:/shared/classical-hp-cross.crt"
    [pqc-hp-cross]="ctp-entity-pqc:/shared/pqc-hp-cross.crt"
    [classical-client]="ctp-entity-classical:/shared/pure-classical-client.crt"
    [pqc-client]="ctp-entity-pqc:/shared/pure-pqc-client.crt"
    [classical-hp-client]="ctp-classical-hp:/shared/classical-hp-client.crt"
    [pqc-hp-client]="ctp-pqc-hp:/shared/pqc-hp-client.crt"
  )

  PARSER="$SCRIPT_DIR/cert_crypto_size.py"
  for name in "${!FILES[@]}"; do
    container=${FILES[$name]%%:*}
    path=${FILES[$name]#*:}
    tmp="/tmp/size-$name.pem"
    docker exec "$container" cat "$path" > "$tmp"
    wc -c "$tmp" | awk '{print $1}' > "$RD/${level}_size-${name}.txt"
    out=$(python3 "$PARSER" "$tmp" 2>/dev/null || true)
    CL=$(echo "$out" | awk '{print $1}'); PQ=$(echo "$out" | awk '{print $2}')
    CL=${CL:-0}; PQ=${PQ:-0}
    echo "$CL" > "$RD/${level}_size-${name}_classical.txt"
    echo "$PQ" > "$RD/${level}_size-${name}_pqc.txt"
    rm -f "$tmp"
  done

  bash "$BASE/run_level.sh" "$level" down
done
