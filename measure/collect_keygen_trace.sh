#!/usr/bin/env bash
# Collect HSM keygen timing with PKCS#11 TRACE logging enabled.
#
# Captures two timing layers per keygen invocation:
#   1. qpki QPKI_DEBUG=1 [TIME] lines  -> hsm_keygen, kp_generate, main_start, sub-timers
#   2. libcs_pkcs11_R3.so TRACE log    -> C_GenerateKeyPair (firmware), C_Login (auth)
#
# The trace log isolates the actual firmware-side computation from PKCS#11
# session overhead. Without it, hsm_keygen (~65ms) is dominated by C_Login
# (~40ms) and slot enumeration (~20ms), burying the 2-14ms of real crypto.
#
# Outputs (per algo per batch):
#   timing_data/kc_hsm_<algo>_batch<N>_<tag>_ms.txt
#     <tag> in: hsm_keygen_<algo>, kp_generate_hsm_<algo>, main_start,
#              pkcs11_find_slot, pkcs11_session_pool, pkcs11_find_key,
#              pkcs11_extract_pub,
#              fw_keygen        (NEW: C_GenerateKeyPair duration from trace log)
#              c_login          (NEW: C_Login duration from trace log)
#              c_opensession    (NEW: C_OpenSession duration from trace log)
#
# Usage:
#   cd CTP && bash measure/collect_keygen_trace.sh
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TD="$ROOT/measure/timing_data"
PARSE="$ROOT/measure/parse_cs_pkcs11_log.py"
CONT="ctp-classical-hp"
CFG="/opt/utimaco/p11/cs_pkcs11_R3.cfg"
N="${N:-100}"
ALGOS="${ALGOS:-ecdsa-p256 ecdsa-p384 ecdsa-p521 ml-dsa-44 ml-dsa-65 ml-dsa-87}"

mkdir -p "$TD"

restart_hsm() {
  echo "  Resetting HSM..."
  cd "$ROOT"
  docker compose --profile full stop ctp-sim >/dev/null 2>&1 || true
  docker compose --profile full rm -f ctp-sim >/dev/null 2>&1 || true
  docker compose --profile full up -d ctp-sim >/dev/null 2>&1
  sleep 5
  docker compose --profile full run --rm ctp-hsm-init >/dev/null 2>&1
  sleep 2
  echo "  HSM ready"
}

enable_trace() {
  docker exec "$CONT" sh -c "sed -i 's/^Logging = [0-9]/Logging = 4/' $CFG && rm -f /tmp/cs_pkcs11_R3.log"
}

disable_trace() {
  docker exec "$CONT" sh -c "sed -i 's/^Logging = [0-9]/Logging = 0/' $CFG"
}

echo "=== Enabling PKCS#11 TRACE logging ==="
enable_trace
trap 'echo "=== Restoring Logging=0 ==="; disable_trace' EXIT

# Make sure qpki_timed is deployed
if ! docker exec "$CONT" sh -c "command -v qpki_timed" >/dev/null 2>&1; then
  echo "ERROR: qpki_timed not found in $CONT"
  echo "Build it: cd <reporoot>/hsm/qpki && go build -o qpki_timed ./cmd/qpki"
  echo "Then:    docker cp qpki_timed $CONT:/usr/local/bin/"
  exit 1
fi

for ALGO in $ALGOS; do
  for BATCH in 1 2 3 4 5 6 7 8 9 10; do
    echo "=== $ALGO batch $BATCH (N=$N) ==="
    restart_hsm
    enable_trace

    PREFIX="kc_hsm_${ALGO}_batch${BATCH}"
    STDERR_FILE="/tmp/${PREFIX}_stderr.txt"
    : > "$STDERR_FILE"

    docker exec "$CONT" rm -f /tmp/cs_pkcs11_R3.log

    for i in $(seq 1 "$N"); do
      KEY_LABEL="kg-$(date +%s)-$RANDOM"
      timeout 30 docker exec "$CONT" sh -c "
        QPKI_DEBUG=1 qpki_timed key gen -a '$ALGO' \
          --hsm-config /etc/qpki/utimaco-simulator.yaml \
          --key-label '$KEY_LABEL'" \
        >/dev/null 2>>"$STDERR_FILE" || true
    done

    echo "  Extracting qpki [TIME] lines..."
    grep '\[TIME\] hsm_keygen'        "$STDERR_FILE" | sed 's/.*: //; s/ms//' > "$TD/${PREFIX}_hsm_keygen_${ALGO}_ms.txt"
    grep '\[TIME\] kp_generate'       "$STDERR_FILE" | sed 's/.*: //; s/ms//' > "$TD/${PREFIX}_kp_generate_hsm_${ALGO}_ms.txt"
    grep '\[TIME\] pkcs11_find_slot'  "$STDERR_FILE" | sed 's/.*: //; s/ms//' > "$TD/${PREFIX}_pkcs11_find_slot_ms.txt"
    grep '\[TIME\] pkcs11_session_pool' "$STDERR_FILE" | sed 's/.*: //; s/ms//' > "$TD/${PREFIX}_pkcs11_session_pool_ms.txt"
    grep '\[TIME\] pkcs11_find_key'   "$STDERR_FILE" | sed 's/.*: //; s/ms//' > "$TD/${PREFIX}_pkcs11_find_key_ms.txt"
    grep '\[TIME\] pkcs11_extract_pub' "$STDERR_FILE" | sed 's/.*: //; s/ms//' > "$TD/${PREFIX}_pkcs11_extract_pub_ms.txt"
    grep '\[TIME\] main_start'        "$STDERR_FILE" | sed 's/.*: //; s/ms//' > "$TD/${PREFIX}_main_start_ms.txt"

    echo "  Extracting PKCS#11 TRACE call durations..."
    TRACE_LOCAL="/tmp/${PREFIX}_trace.log"
    docker exec "$CONT" cat /tmp/cs_pkcs11_R3.log > "$TRACE_LOCAL" 2>/dev/null || true

    if [ -s "$TRACE_LOCAL" ]; then
      python3 "$PARSE" "$TRACE_LOCAL" C_GenerateKeyPair | awk '{print $2}' > "$TD/${PREFIX}_fw_keygen_ms.txt"
      python3 "$PARSE" "$TRACE_LOCAL" C_Login          | awk '{print $2}' > "$TD/${PREFIX}_c_login_ms.txt"
      python3 "$PARSE" "$TRACE_LOCAL" C_OpenSession    | awk '{print $2}' > "$TD/${PREFIX}_c_opensession_ms.txt"
    else
      : > "$TD/${PREFIX}_fw_keygen_ms.txt"
      : > "$TD/${PREFIX}_c_login_ms.txt"
      : > "$TD/${PREFIX}_c_opensession_ms.txt"
    fi

    for tag in hsm_keygen_${ALGO} kp_generate_hsm_${ALGO} main_start fw_keygen c_login; do
      f="$TD/${PREFIX}_${tag}_ms.txt"
      samp=$(wc -l < "$f" 2>/dev/null | tr -d ' ' || echo 0)
      echo "    $tag: ${samp} samples"
    done
    errors=$(grep -c "Error:" "$STDERR_FILE" 2>/dev/null | head -1 || echo 0)
    if [ "${errors:-0}" -gt 0 ] 2>/dev/null; then
      echo "    WARNING: $errors iterations failed"
    fi
  done
done

echo "=== Done. Trace logging restored to Logging=0. ==="
