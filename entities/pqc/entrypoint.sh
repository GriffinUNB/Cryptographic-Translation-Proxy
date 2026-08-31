#!/bin/bash
set -e

CA_DIR=/ca/entity-pqc
SHARED_DIR=/shared
PIN=${HSM_PIN:-UserPwd1234!X}
CA_PASSPHRASE=${CA_PASSPHRASE:-CTPLab2026}
CTP_MODE=${CTP_MODE:-proxy}
PQC_ROOT_PROFILE=${PQC_ROOT_PROFILE:-ml/root-ca}
PQC_ISSUING_PROFILE=${PQC_ISSUING_PROFILE:-ml/issuing-ca}

mkdir -p "$CA_DIR" "$SHARED_DIR"

export CRYPTOSERVER=3001@ctp-sim
export HSM_PIN="$PIN"
export HSM_PQC_ENABLED=1

if [ ! -f "$CA_DIR/ca.crt" ]; then
    echo "Entity PQC: Initializing PQC Root CA ($PQC_ROOT_PROFILE, Utimaco HSM)..."
    qpki ca init \
        --profile "$PQC_ROOT_PROFILE" \
        --ca-dir "$CA_DIR" \
        --var cn="PQC Entity" \
        --passphrase "$CA_PASSPHRASE" \
        --hsm-config /etc/qpki/utimaco-simulator.yaml \
        --key-label "entity-pqc-key"

    qpki ca export --ca-dir "$CA_DIR" --out "$CA_DIR/ca.crt"
    echo "Entity PQC: PQC Root CA initialized"
fi

cp "$CA_DIR/ca.crt" "$SHARED_DIR"/entity-pqc.crt

if [ "$CTP_MODE" = "proxy" ]; then
    echo "Entity PQC: Waiting for HP's PQC CSR..."
    for i in $(seq 1 120); do
        if [ -f "$SHARED_DIR/pqc-hp-cross.csr" ]; then
            echo "Entity PQC: Cross-signing HP's CSR..."
            qpki cert issue \
                --ca-dir "$CA_DIR" \
                --profile "$PQC_ISSUING_PROFILE" \
                --csr "$SHARED_DIR/pqc-hp-cross.csr" \
                --out "$SHARED_DIR/pqc-hp-cross.crt" \
                --var cn="Hybrid Proxy PQC (HP)" \
                --ca-passphrase "$CA_PASSPHRASE"
            echo "Entity PQC: Cross-signed HP's CSR"
            break
        fi
        if [ $i -eq 120 ]; then echo "ERROR: pqc timed out waiting for HP's CSR"; exit 1; fi
        sleep 1
    done
fi

echo "Entity PQC: READY (mode=${CTP_MODE})"
tail -f /dev/null