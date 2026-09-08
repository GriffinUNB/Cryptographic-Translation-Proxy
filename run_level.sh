#!/bin/bash
# Run a specific CTP security level.
# Usage: ./run_level.sh <l1|l3|l5> [up|down|restart]
#   up: deploy and wait for READY
#   down: teardown
#   restart: down + up

set -e
cd "$(dirname "$0")" || exit 1

LEVEL="$1"
ACTION="${2:-up}"

case "$LEVEL" in
  l1)
    export CLASSICAL_ROOT_PROFILE=ec/root-ca-l1
    export CLASSICAL_ISSUING_PROFILE=ec/issuing-ca
    export CLASSICAL_CSR_CURVE=prime256v1
    export PQC_ROOT_PROFILE=ml/root-ca-l1
    export PQC_ISSUING_PROFILE=ml/issuing-ca-l1
    export HYBRID_ROOT_PROFILE=hybrid/catalyst/root-ca-l1
    export TLS_CLIENT_PROFILE=hybrid/catalyst/tls-client-l1
    # PQC proxy CSR: ML-DSA-44 (set in compose override below via env)
    export PQC_CSR_ALGO=ml-dsa-44
    LEVEL_LABEL="L1 (P-256 + ML-DSA-44)"
    ;;
  l3)
    export CLASSICAL_ROOT_PROFILE=ec/root-ca
    export CLASSICAL_ISSUING_PROFILE=ec/issuing-ca-l3
    export CLASSICAL_CSR_CURVE=secp384r1
    export PQC_ROOT_PROFILE=ml/root-ca-l3
    export PQC_ISSUING_PROFILE=ml/issuing-ca-l3
    export HYBRID_ROOT_PROFILE=hybrid/catalyst/root-ca-l3
    # TLS_CLIENT_PROFILE stays default (P-256 + ML-DSA-65) — already L3
    export PQC_CSR_ALGO=ml-dsa-65
    LEVEL_LABEL="L3 (P-384 + ML-DSA-65)"
    ;;
  l5)
    export CLASSICAL_ROOT_PROFILE=ec/root-ca-l5
    export CLASSICAL_ISSUING_PROFILE=ec/issuing-ca-l5
    export CLASSICAL_CSR_CURVE=secp521r1
    # PQC_ROOT_PROFILE defaults to ml/root-ca (ML-DSA-87) — already L5
    # PQC_ISSUING_PROFILE defaults to ml/issuing-ca (ML-DSA-65) — need L5 match
    export PQC_ISSUING_PROFILE=ml/issuing-ca
    export HYBRID_ROOT_PROFILE=hybrid/catalyst/root-ca-l5
    export TLS_CLIENT_PROFILE=hybrid/catalyst/tls-client-l5
    export PQC_CSR_ALGO=ml-dsa-87
    LEVEL_LABEL="L5 (P-521 + ML-DSA-87)"
    ;;
  *)
    echo "Usage: $0 <l1|l3|l5> [up|down|restart]"
    exit 1
    ;;
esac

case "$ACTION" in
  up)
    echo "=== Deploying $LEVEL_LABEL ==="
    # Full clean to clear HSM state between levels
    docker compose --profile full down -v 2>/dev/null || true
    docker compose --profile baseline down -v 2>/dev/null || true
    sleep 1
    CLASSICAL_ROOT_PROFILE=$CLASSICAL_ROOT_PROFILE \
    CLASSICAL_ISSUING_PROFILE=${CLASSICAL_ISSUING_PROFILE:-ec/issuing-ca} \
    CLASSICAL_CSR_CURVE=${CLASSICAL_CSR_CURVE:-prime256v1} \
    PQC_ROOT_PROFILE=$PQC_ROOT_PROFILE \
    PQC_ISSUING_PROFILE=$PQC_ISSUING_PROFILE \
    HYBRID_ROOT_PROFILE=$HYBRID_ROOT_PROFILE \
    TLS_CLIENT_PROFILE=${TLS_CLIENT_PROFILE:-hybrid/catalyst/tls-client} \
    docker compose --profile full up -d

    echo "Waiting for all containers to be READY..."
    for container in ctp-entity-classical ctp-entity-pqc ctp-classical-hp ctp-pqc-hp; do
        echo -n "  $container: "
        for i in $(seq 1 120); do
            logs=$(docker logs "$container" 2>&1)
            # Entity: look for "READY" last; Proxy: look for client cert issued
            if echo "$logs" | grep -q "Hybrid client certificate issued"; then
                echo "READY (${i}s)"
                break
            fi
            if echo "$logs" | grep -q "READY (mode="; then
                echo "READY (${i}s)"
                break
            fi
            if [ $i -eq 120 ]; then echo "TIMEOUT"; exit 1; fi
            sleep 1
        done
    done
    echo "=== Level $LEVEL_LABEL deployed ==="
    ;;
  down)
    echo "=== Tearing down $LEVEL_LABEL ==="
    docker compose --profile full down -v
    echo "=== Done ==="
    ;;
  restart)
    $0 "$LEVEL" down
    $0 "$LEVEL" up
    ;;
esac
