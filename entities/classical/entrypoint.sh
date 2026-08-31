#!/bin/bash
set -e

CA_DIR=/ca/entity-classical
SHARED_DIR=/shared
PIN=${HSM_PIN:-UserPwd1234!X}
CA_PASSPHRASE=${CA_PASSPHRASE:-CTPLab2026}
CTP_MODE=${CTP_MODE:-proxy}
CLASSICAL_ROOT_PROFILE=${CLASSICAL_ROOT_PROFILE:-ec/root-ca}
CLASSICAL_ISSUING_PROFILE=${CLASSICAL_ISSUING_PROFILE:-ec/issuing-ca}

mkdir -p "$CA_DIR" "$SHARED_DIR"

export CRYPTOSERVER=3001@ctp-sim
export HSM_PIN="$PIN"
export HSM_PQC_ENABLED=1

if [ ! -f "$CA_DIR/ca.crt" ]; then
    echo "Entity Classical: Initializing classical Root CA ($CLASSICAL_ROOT_PROFILE, Utimaco HSM)..."
    qpki ca init \
        --profile "$CLASSICAL_ROOT_PROFILE" \
        --ca-dir "$CA_DIR" \
        --var cn="Classical Entity" \
        --passphrase "$CA_PASSPHRASE" \
        --hsm-config /etc/qpki/utimaco-simulator.yaml \
        --key-label "entity-classical-key"

    qpki ca export --ca-dir "$CA_DIR" --out "$CA_DIR/ca.crt"
    echo "Entity Classical: Classical Root CA initialized"
fi

cp "$CA_DIR/ca.crt" "$SHARED_DIR"/entity-classical.crt

if [ "$CTP_MODE" = "proxy" ]; then
    echo "Entity Classical: Waiting for HP's CSR..."
    for i in $(seq 1 120); do
        if [ -f "$SHARED_DIR/classical-hp-cross.csr" ]; then
            echo "Entity Classical: Cross-signing HP's CSR..."
            qpki cert issue \
                --ca-dir "$CA_DIR" \
                --profile "$CLASSICAL_ISSUING_PROFILE" \
                --csr "$SHARED_DIR/classical-hp-cross.csr" \
                --out "$SHARED_DIR/classical-hp-cross.crt" \
                --var cn="Hybrid Proxy Classical (HP)" \
                --ca-passphrase "$CA_PASSPHRASE"
            echo "Entity Classical: Cross-signed HP's CSR"
            break
        fi
        if [ $i -eq 120 ]; then echo "ERROR: classical timed out waiting for HP's CSR"; exit 1; fi
        sleep 1
    done
fi

echo "Entity Classical: READY (mode=${CTP_MODE})"
tail -f /dev/null