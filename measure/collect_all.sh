#!/bin/bash
# Instrumented timing collection for all 3 levels.
# Usage: bash collect_all.sh [level]
#   level=all (default), l1, l3, l5

set -euo pipefail

# Paths are relative to this script's location (measure/), so a fresh checkout
# reproduces entirely within its own directory.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE="$(cd "$SCRIPT_DIR/.." && pwd)"
TD="$SCRIPT_DIR/timing_data"
SAMPLES="${SAMPLES:-1000}"
WARMUP="${WARMUP:-100}"
LEVEL="${1:-all}"

# A full run owns all output; single-level runs only replace that level by default.
if [[ "$LEVEL" == "all" || "${WIPE_DATA:-0}" == "1" ]]; then
  rm -f "$TD"/*.txt
fi

collect_level() {
  local level=$1 pqc=$2 tlsprof=$3
  echo ""
  echo "============================================"
  echo "  $level"
  echo "============================================"

  case "$level" in
    l1)
      classical_root=ec/root-ca-l1
      classical_issuing=ec/issuing-ca
      pqc_root=ml/root-ca-l1
      pqc_issuing=ml/issuing-ca-l1
      hybrid_root=hybrid/catalyst/root-ca-l1
      classical_client=ec/tls-client
      pqc_client=ml/tls-client-l1
      C_ALGO=ecdsa-p256
      P_ALGO=ml-dsa-44
      ;;
    l3)
      classical_root=ec/root-ca
      classical_issuing=ec/issuing-ca
      pqc_root=ml/root-ca-l3
      pqc_issuing=ml/issuing-ca-l3
      hybrid_root=hybrid/catalyst/root-ca-l3
      classical_client=ec/tls-client-l3
      pqc_client=ml/tls-client
      C_ALGO=ecdsa-p384
      P_ALGO=ml-dsa-65
      ;;
    l5)
      classical_root=ec/root-ca-l5
      classical_issuing=ec/issuing-ca-l5
      pqc_root=ml/root-ca
      pqc_issuing=ml/issuing-ca
      hybrid_root=hybrid/catalyst/root-ca-l5
      classical_client=ec/tls-client-l5
      pqc_client=ml/tls-client-l5
      C_ALGO=ecdsa-p521
      P_ALGO=ml-dsa-87
      ;;
  esac
  
  cd "$BASE"
  output=$(bash run_level.sh $level up 2>&1)
  echo "$output"
  if echo "$output" | grep -q "TIMEOUT"; then
    echo "FATAL: Level $level deployment timed out"
    exit 1
  fi

  for c in ctp-entity-classical ctp-entity-pqc ctp-classical-hp ctp-pqc-hp; do
    docker cp "$BASE/hsm/qpki_timed" "$c:/usr/local/bin/qpki"
  done

  echo "  CSRs..."
  docker exec ctp-classical-hp sh -c "
    qpki key gen -a ecdsa-p256 -o /tmp/ec-bench.pem 2>/dev/null
    qpki csr gen --key /tmp/ec-bench.pem --hybrid $pqc --hybrid-keyout /tmp/ml-bench.pem --hybrid-passphrase temp --cn 'bench-hybrid' -o /tmp/bench-hybrid.csr --key-passphrase temp
    openssl ecparam -genkey -name prime256v1 -out /tmp/ec-key.pem 2>/dev/null
    openssl req -new -key /tmp/ec-key.pem -subj '/CN=bench-ec/O=CTP/C=US' -out /tmp/bench-ec.csr 2>/dev/null
  " 2>&1 | tail -1
  docker exec ctp-pqc-hp sh -c "
    qpki key gen -a $pqc -o /tmp/ml-entity.pem -p temp 2>/dev/null
    qpki csr gen --key /tmp/ml-entity.pem --passphrase temp --cn 'bench-pqc' -o /tmp/bench-pqc.csr 2>/dev/null
  " 2>&1 | tail -1

  docker cp ctp-classical-hp:/tmp/bench-ec.csr /tmp/bench-ec.csr 2>/dev/null || { echo "FATAL: bench-ec.csr not found"; exit 1; }
  for c in ctp-entity-classical ctp-classical-hp; do docker cp /tmp/bench-ec.csr "$c:/tmp/bench-ec.csr"; done
  docker cp ctp-classical-hp:/tmp/bench-hybrid.csr /tmp/bench-hybrid.csr 2>/dev/null || { echo "FATAL: bench-hybrid.csr not found"; exit 1; }
  for c in ctp-classical-hp ctp-pqc-hp; do docker cp /tmp/bench-hybrid.csr "$c:/tmp/bench-hybrid.csr"; done
  docker cp ctp-pqc-hp:/tmp/bench-pqc.csr /tmp/bench-pqc.csr 2>/dev/null || { echo "FATAL: bench-pqc.csr not found"; exit 1; }
  for c in ctp-entity-pqc ctp-pqc-hp; do docker cp /tmp/bench-pqc.csr "$c:/tmp/bench-pqc.csr"; done

  echo "  Client certs..."
  docker exec ctp-classical-hp sh -c "
    qpki credential enroll --ca-dir /ca/classical-hp --cred-dir /certs --profile $tlsprof --var cn='client-v2' --id 'client-v2' --passphrase CTPLab2026 2>/dev/null
    qpki credential export --cred-dir /certs 'client-v2' --bundle all --out /shared/classical-hp-client-v2.crt 2>/dev/null
  "
  docker exec ctp-pqc-hp sh -c "
    qpki credential enroll --ca-dir /ca/pqc-hp --cred-dir /certs --profile $tlsprof --var cn='client-v2' --id 'client-v2' --passphrase CTPLab2026 2>/dev/null
    qpki credential export --cred-dir /certs 'client-v2' --bundle all --out /shared/pqc-hp-client-v2.crt 2>/dev/null
  "

  echo "  Pure client certs..."
  docker exec ctp-entity-classical sh -c "
    qpki key gen -a '$C_ALGO' -o /tmp/pure-classical-key.pem -p temp 2>/dev/null
    qpki csr gen --key /tmp/pure-classical-key.pem --passphrase temp --cn pure-classical-client -o /tmp/pure-classical.csr 2>/dev/null
    qpki cert issue --ca-dir /ca/entity-classical --csr /tmp/pure-classical.csr --profile /opt/qpki/profiles/'$classical_client'.yaml --out /shared/pure-classical-client.crt --var cn=pure-classical-client --ca-passphrase CTPLab2026 2>/dev/null
  "
  docker exec ctp-entity-pqc sh -c "
    qpki key gen -a '$P_ALGO' -o /tmp/pure-pqc-key.pem -p temp 2>/dev/null
    qpki csr gen --key /tmp/pure-pqc-key.pem --passphrase temp --cn pure-pqc-client -o /tmp/pure-pqc.csr 2>/dev/null
    qpki cert issue --ca-dir /ca/entity-pqc --csr /tmp/pure-pqc.csr --profile /opt/qpki/profiles/'$pqc_client'.yaml --out /shared/pure-pqc-client.crt --var cn=pure-pqc-client --ca-passphrase CTPLab2026 2>/dev/null
  "

  restart_hsm() {
    echo "  Restarting lab (HSM wipe + CA re-keygen)..."
    cd "$BASE"
    docker compose --profile full stop >/dev/null 2>&1 || true
    docker compose --profile full rm -f >/dev/null 2>&1 || true
    CLASSICAL_ROOT_PROFILE="$classical_root" \
    CLASSICAL_ISSUING_PROFILE="$classical_issuing" \
    PQC_ROOT_PROFILE="$pqc_root" \
    PQC_ISSUING_PROFILE="$pqc_issuing" \
    HYBRID_ROOT_PROFILE="$hybrid_root" \
    TLS_CLIENT_PROFILE="$tlsprof" \
      docker compose --profile full up -d >/dev/null 2>&1
    for c in ctp-entity-classical ctp-entity-pqc ctp-classical-hp ctp-pqc-hp; do
      for i in $(seq 1 120); do
        docker logs $c 2>&1 | tail -20 | grep -q "READY" && break
        sleep 1
      done
    done
    sleep 5
    for c in ctp-entity-classical ctp-entity-pqc ctp-classical-hp ctp-pqc-hp; do
      docker cp "$BASE/hsm/qpki_timed" "$c:/usr/local/bin/qpki" 2>/dev/null || true
      docker cp /tmp/bench-ec.csr     "$c:/tmp/bench-ec.csr"     2>/dev/null || true
      docker cp /tmp/bench-pqc.csr    "$c:/tmp/bench-pqc.csr"    2>/dev/null || true
      docker cp /tmp/bench-hybrid.csr "$c:/tmp/bench-hybrid.csr" 2>/dev/null || true
    done
    docker exec ctp-classical-hp sh -c "qpki credential enroll --ca-dir /ca/classical-hp --cred-dir /certs --profile '$tlsprof' --var cn='client-v2' --id 'client-v2' --passphrase CTPLab2026 2>/dev/null && qpki credential export --cred-dir /certs 'client-v2' --bundle all --out /shared/classical-hp-client-v2.crt 2>/dev/null"
    docker exec ctp-pqc-hp sh -c "qpki credential enroll --ca-dir /ca/pqc-hp --cred-dir /certs --profile '$tlsprof' --var cn='client-v2' --id 'client-v2' --passphrase CTPLab2026 2>/dev/null && qpki credential export --cred-dir /certs 'client-v2' --bundle all --out /shared/pqc-hp-client-v2.crt 2>/dev/null"
    echo "  Lab ready"
  }

  # Wipe + re-init lab for instrumented pass (reset HSM op counter, regenerate CA keys)
  restart_hsm

  echo "  Issue instrumented..."
  for ent in "ctp-entity-classical:classical_ca:bench-ec.csr:ec/tls-client" \
             "ctp-entity-pqc:pqc_ca:bench-pqc.csr:ml/tls-client" \
             "ctp-classical-hp:classicalhp:bench-hybrid.csr:$tlsprof" \
             "ctp-pqc-hp:pqchp:bench-hybrid.csr:$tlsprof"; do
    cont=$(echo $ent | cut -d: -f1); key=$(echo $ent | cut -d: -f2)
    csr=$(echo $ent | cut -d: -f3); prof=$(echo $ent | cut -d: -f4)
    # Map container name to CA directory
    case "$cont" in
      ctp-entity-classical) ca_dir="/ca/entity-classical" ;;
      ctp-entity-pqc)      ca_dir="/ca/entity-pqc" ;;
      ctp-classical-hp)    ca_dir="/ca/classical-hp" ;;
      ctp-pqc-hp)          ca_dir="/ca/pqc-hp" ;;
    esac
     echo "    $key (dir=$ca_dir)..."
     # Double quotes for sh -c so host expands $ca_dir/$csr/$prof; \$ prevents $(seq) expansion on host
     docker exec -e QPKI_DEBUG=1 "$cont" sh -c "
       for i in \$(seq 1 "$WARMUP"); do
         qpki cert issue --ca-dir '$ca_dir' --csr /tmp/'$csr' --profile '$prof' --out /dev/null --var cn=warmup --ca-passphrase CTPLab2026 > /dev/null 2>&1 || true
       done
       for i in \$(seq 1 "$SAMPLES"); do
         qpki cert issue --ca-dir '$ca_dir' --csr /tmp/'$csr' --profile '$prof' --out /dev/null --var cn=bench --ca-passphrase CTPLab2026 > /dev/null || true
       done
    " 2>/tmp/ts.txt || true
    grep '\[TIME\]' /tmp/ts.txt | awk '{print $2}' | sed 's/:$//' | sort -u | while IFS= read -r tag; do
       grep "\[TIME\] $tag" /tmp/ts.txt | sed 's/.*\[TIME\] [^:]*: *//; s/ms//' > "$TD/${level}_issue_${key}_${tag}_ms.txt"
       count=$(wc -l < "$TD/${level}_issue_${key}_${tag}_ms.txt")
       [ "$count" -ge "$SAMPLES" ] || { echo "FATAL: $level $key $tag sample count=$count"; exit 1; }
     done
     for tag in main_start issue_total; do
       test -f "$TD/${level}_issue_${key}_${tag}_ms.txt" || {
         echo "FATAL: $level $key missing required timer $tag"
         exit 1
       }
       count=$(wc -l < "$TD/${level}_issue_${key}_${tag}_ms.txt")
       [ "$count" -eq "$SAMPLES" ] || { echo "FATAL: $level $key $tag sample count=$count"; exit 1; }
     done
    [ "$key" != "pqchp" ] && restart_hsm  # ponytail: re-keygen outlier in first sample of next entity
  done

  echo "  Verify instrumented..."
  for ent in "verify_classical:ctp-entity-classical:/ca/entity-classical/ca.crt:/ca/entity-classical/ca.crt" \
             "verify_pqc:ctp-entity-pqc:/ca/entity-pqc/ca.crt:/ca/entity-pqc/ca.crt" \
             "verify_classicalhp:ctp-entity-classical:/shared/classical-hp-client-v2.crt:/shared/classical-hp-self-signed.crt" \
             "verify_pqchp:ctp-entity-pqc:/shared/pqc-hp-client-v2.crt:/shared/pqc-hp-self-signed.crt"; do
    key=$(echo $ent | cut -d: -f1); cont=$(echo $ent | cut -d: -f2)
    cert=$(echo $ent | cut -d: -f3); ca=$(echo $ent | cut -d: -f4)
    echo "    $key..."
    # Remove prior micro timer files so only this run's data remains.
    rm -f "$TD/${level}_${key}_main_start_ms.txt" \
          "$TD/${level}_${key}_verify_"*.txt
    docker exec -e QPKI_DEBUG=1 "$cont" sh -c '
       for i in $(seq 1 '"$WARMUP"'); do
         qpki cert verify '"$cert"' --ca '"$ca"' > /dev/null 2>&1 || true
       done
       for i in $(seq 1 '"$SAMPLES"'); do
         qpki cert verify '"'$cert'"' --ca '"'$ca'"' > /dev/null || true
       done
    ' 2>/tmp/ts.txt || true
     grep '\[TIME\]' /tmp/ts.txt | awk '{print $2}' | sed 's/:$//' | sort -u | while IFS= read -r tag; do
       grep "\[TIME\] $tag" /tmp/ts.txt | sed 's/.*\[TIME\] [^:]*: *//; s/ms//' > "$TD/${level}_${key}_${tag}_ms.txt"
       count=$(wc -l < "$TD/${level}_${key}_${tag}_ms.txt")
       [ "$count" -eq "$SAMPLES" ] || { echo "FATAL: $level $key $tag sample count=$count"; exit 1; }
     done
     required="main_start verify_total verify_sig verify_check_sig"
     case "$key" in
       verify_classical) required="$required verify_stdlib" ;;
       verify_pqc) required="$required verify_circl" ;;
       *) required="$required verify_stdlib verify_circl" ;;
     esac
     for tag in $required; do
       test -f "$TD/${level}_${key}_${tag}_ms.txt" || {
         echo "FATAL: $level $key missing required timer $tag"
         exit 1
       }
     done
   done

  echo "  $level done"
}

case "$LEVEL" in
  all|"") collect_level "l1" "ml-dsa-44" "hybrid/catalyst/tls-client-l1"
          collect_level "l3" "ml-dsa-65" "hybrid/catalyst/tls-client"
          collect_level "l5" "ml-dsa-87" "hybrid/catalyst/tls-client-l5" ;;
  l1)     collect_level "l1" "ml-dsa-44" "hybrid/catalyst/tls-client-l1" ;;
  l3)     collect_level "l3" "ml-dsa-65" "hybrid/catalyst/tls-client" ;;
  l5)     collect_level "l5" "ml-dsa-87" "hybrid/catalyst/tls-client-l5" ;;
  *)      echo "Usage: $0 [all|l1|l3|l5]"; exit 1 ;;
esac

echo ""
echo "=== All collection complete ==="
ls "$TD"/*.txt 2>/dev/null | wc -l
echo "timing files created"
