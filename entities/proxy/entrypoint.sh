#!/bin/bash
set -e

: "${PROXY_NAME:?PROXY_NAME required (e.g. classical-hp)}"
: "${CN_LABEL:?CN_LABEL required (e.g. Classical)}"
: "${CSR_ALGO:?CSR_ALGO required (ecdsa-p256 or ml-dsa-*)}"
: "${CLASSICAL_CSR_CURVE:=prime256v1}"

CA_DIR=/ca/$PROXY_NAME
SHARED_DIR=/shared
PIN=${HSM_PIN:-UserPwd1234!X}
CA_PASSPHRASE=${CA_PASSPHRASE:-CTPLab2026}
KEY_LABEL="${PROXY_NAME}-catalyst-key"
CN="Hybrid Proxy ${CN_LABEL} (${PROXY_NAME^^})"
HYBRID_ROOT_PROFILE=${HYBRID_ROOT_PROFILE:-hybrid/catalyst/root-ca}
TLS_CLIENT_PROFILE=${TLS_CLIENT_PROFILE:-hybrid/catalyst/tls-client}

mkdir -p "$CA_DIR" "$SHARED_DIR"

export CRYPTOSERVER=3001@ctp-sim
export HSM_PIN="$PIN"
export HSM_PQC_ENABLED=1

if [ ! -f "$CA_DIR/ca.crt" ]; then
    echo "${PROXY_NAME}: Initializing hybrid Root CA ($HYBRID_ROOT_PROFILE, Utimaco HSM)..."
    qpki ca init \
        --profile "$HYBRID_ROOT_PROFILE" \
        --ca-dir "$CA_DIR" \
        --var cn="$CN" \
        --passphrase "$CA_PASSPHRASE" \
        --hsm-config /etc/qpki/utimaco-simulator.yaml \
        --key-label "$KEY_LABEL"

    qpki ca export --ca-dir "$CA_DIR" --out "$CA_DIR/ca.crt"
    echo "${PROXY_NAME}: Hybrid root CA initialized (EC + ML-DSA, HSM)"
fi

qpki ca export --ca-dir "$CA_DIR" --out "$SHARED_DIR/$PROXY_NAME-self-signed.crt"

echo "${PROXY_NAME}: Generating ${CSR_ALGO} CSR..."
if [[ "$CSR_ALGO" == ml-dsa-* ]]; then
    qpki key gen -a "$CSR_ALGO" -o "/tmp/$PROXY_NAME-csr-key.pem" -p csrtemp 2>/dev/null
    qpki csr gen \
        --key "/tmp/$PROXY_NAME-csr-key.pem" \
        --passphrase csrtemp \
        --cn "$CN" \
        --org "ACME Corp" \
        --country US \
        --out "$SHARED_DIR/$PROXY_NAME-cross.csr"
else
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:"$CLASSICAL_CSR_CURVE" -out "/tmp/$PROXY_NAME-csr-key.pem" 2>/dev/null
    qpki csr gen \
        --key "/tmp/$PROXY_NAME-csr-key.pem" \
        --cn "$CN" \
        --org "ACME Corp" \
        --country US \
        --out "$SHARED_DIR/$PROXY_NAME-cross.csr"
fi

echo "${PROXY_NAME}: READY"

echo "${PROXY_NAME}: Waiting for cross-signed cert..."
for i in $(seq 1 120); do
    if [ -f "$SHARED_DIR/$PROXY_NAME-cross.crt" ]; then
        echo "${PROXY_NAME}: Cross-signed certificate received"
        cp "$SHARED_DIR/$PROXY_NAME-cross.crt" "$CA_DIR/$PROXY_NAME-cross.crt"
        break
    fi
    if [ $i -eq 120 ]; then echo "${PROXY_NAME}: ERROR - timed out waiting for cross-signed cert"; exit 1; fi
    sleep 1
done

echo "${PROXY_NAME}: Issuing hybrid (Catalyst) client certificate..."
if [ ! -f "$SHARED_DIR/$PROXY_NAME-client.crt" ]; then
    qpki credential enroll \
        --ca-dir "$CA_DIR" \
        --cred-dir /certs \
        --profile "$TLS_CLIENT_PROFILE" \
        --var cn="client.$PROXY_NAME" \
        --id "client-$PROXY_NAME" \
        --passphrase "$CA_PASSPHRASE"

    qpki credential export --cred-dir /certs "client-$PROXY_NAME" --bundle all --out "$SHARED_DIR/$PROXY_NAME-client.crt"
    echo "${PROXY_NAME}: Hybrid client certificate issued (EC + ML-DSA, HSM)"
fi

tail -f /dev/null
