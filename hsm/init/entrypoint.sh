#!/bin/sh
set -e

if [ ! -f /opt/utimaco/p11/libcs_pkcs11_R3.so ]; then
    echo "FATAL: PKCS#11 library not found"
    exit 1
fi

init_token() {
    export CRYPTOSERVER=3001@ctp-sim
    export CS_PKCS11_R3_CFG=/opt/utimaco/p11/cs_pkcs11_R3.cfg

    for i in $(seq 1 30); do
        INFO=$(p11tool2 GetTokenInfo 2>/dev/null) || { sleep 2; continue; }

        if echo "$INFO" | grep -q "CKF_USER_PIN_INITIALIZED.*CK_TRUE"; then
            echo "Token already initialized, ready"
            return 0
        fi

        if echo "$INFO" | grep -q "CKF_TOKEN_INITIALIZED.*CK_TRUE"; then
            p11tool2 LoginSO=12345677 SetPIN=12345677,SOpin12345! 2>/dev/null && \
            p11tool2 LoginSO=SOpin12345! InitPIN=UserPwd1234! 2>/dev/null && \
            p11tool2 LoginUser=UserPwd1234! SetPIN=UserPwd1234!,UserPwd1234!X 2>/dev/null
            echo "Token initialized (User PIN set)"
            return 0
        fi

        p11tool2 Login=ADMIN,/opt/utimaco/keys/ADMIN_SIM.key \
            Label="CA-Token" InitToken=12345677 2>/dev/null && \
        p11tool2 LoginSO=12345677 SetPIN=12345677,SOpin12345! 2>/dev/null && \
        p11tool2 LoginSO=SOpin12345! InitPIN=UserPwd1234! 2>/dev/null && \
        p11tool2 LoginUser=UserPwd1234! SetPIN=UserPwd1234!,UserPwd1234!X 2>/dev/null
        echo "Token initialized from scratch"
        return 0
    done
    echo "FATAL: Failed to initialize token after 30 attempts"
    exit 1
}

init_token
echo "HSM token initialization complete"
