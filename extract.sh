#!/bin/bash
set -euo pipefail

# Rebuild the Utimaco-derived files into the CTP/hsm directory.
# Place the two vendor zips in this directory (CTP/) and run: ./extract.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

GP_HSM_ZIP="$SCRIPT_DIR/u.trust-GP-HSM-Simulator_v6.5.0.0.zip"
QP_ZIP="$SCRIPT_DIR/QuantumProtect-1.5.0.0-Evaluation.zip"

CTP_HSM="${CTP_HSM:-$(realpath "$SCRIPT_DIR/hsm")}"

GP_HSM_ZIP_SHA="22189a0bdf2a778480c2daa5792baeb5"
QP_ZIP_SHA="94c254976931866b3f6fa9636da82d87"

EXPECT_SHA="
sim/bl_sim5  d495883967d482d76d4d4dbcc062594e
sim/cs_sim.ini  6e6b27b65540f75977f4779d2bcdb02c
sim/devices/ALARM.curr  9ab3610810246dfcd5a6fd44e491401b
sim/devices/FLASHFILE  5062addc9ad887cb7da0644d46a3de81
sim/devices/MK  c4a0f022523ea4bfbca8a288fa825997
sim/devices/NVRAMFILE  686801f312d486021030db8a9a27e042
sim/devices/swap.com  d41d8cd98f00b204e9800998ecf8427e
sim/devices/SDRAM/adm.so  77f0c85563fdee0f71ac5c83b8622d96
sim/devices/SDRAM/cmds.so  7a0f55279eeadc4480bba6c43e69891e
sim/devices/SDRAM/crypt.so  555890e9e3e3d62fff9ccf0465acc078
sim/devices/SDRAM/cxi.so  1138ab7d1343e0c18697854bfa6f0046
sim/devices/SDRAM/db.so  ee0b49ae5e05018a2cc613102f87a8bd
sim/devices/SDRAM/hbs.so  9a3b8e920ccfd5771bbd1272a840b65d
sim/devices/SDRAM/mbk.so  a89f69c01fdbd70dfe6a4266f3567468
sim/devices/SDRAM/ml.so  cf279f94c55cda164bbbe8f9b4060bb7
sim/devices/SDRAM/pp.so  de27496a8d1e12637770174f43f8361a
sim/devices/SDRAM/pqmi.so  ab7d0c777d423e59a62ee0b45befa17c
sim/devices/SDRAM/sc.so  e0be7103a3ad501be432047f98f0752d
sim/devices/SDRAM/smos.so  9eb9f2128a567dc7be936f69b5ca4722
sim/devices/SDRAM/stun.so  77c440ebe3a6535b663054b21cdac390
sim/devices/SDRAM/util.so  081356bd1fdb99ade18a2efa9005c855
libcs_pkcs11_R3.so  abae159f07c78e023d4fcbfb2ad21140
libcxi.so  3fb9d4eb07ee791f71286c4ca50a94a6
csadm  51595c6bd83d2d460297dd365332db45
cxitool  9fd7bac1878bd070dcd80239f0b47e08
p11tool2  0bb4290feba40edb2d1bc2a4f626ee3d
keys/ADMIN_EC.key  7b5cb8234c19038ed86848a5acd868ef
keys/ADMIN.key  5e11b94c00cb0d252228d5e243608cf3
keys/ADMIN_SIM.key  b90699625ddfa3093ee9187af10d9735
keys/giak.pem  84ed468e71db85d11240644b9b4be6a5
"

log() { echo "[extract.sh] $*"; }

missing=0
for z in "$GP_HSM_ZIP" "$QP_ZIP"; do
  if [[ ! -f "$z" ]]; then
    echo "ERROR: required zip not found in $(basename "$SCRIPT_DIR"): $(basename "$z")" >&2
    missing=1
  fi
done
if [[ $missing -eq 1 ]]; then
  echo "       Place these in $SCRIPT_DIR then re-run:" >&2
  echo "         u.trust-GP-HSM-Simulator_v6.5.0.0.zip" >&2
  echo "         QuantumProtect-1.5.0.0-Evaluation.zip" >&2
  exit 1
fi

log "verifying input zip checksums"
FAILED_ZIPS=0
for entry in "$GP_HSM_ZIP:$GP_HSM_ZIP_SHA" "$QP_ZIP:$QP_ZIP_SHA"; do
  z="${entry%%:*}"; want="${entry##*:}"
  got="$(md5sum "$z" | awk '{print $1}')"
  if [[ "$got" == "$want" ]]; then
    log "  ok    $(basename "$z")  $got"
  else
    log "  FAIL  $(basename "$z")  got=$got  expected=$want" >&2
    FAILED_ZIPS=1
  fi
done
if [[ $FAILED_ZIPS -eq 1 ]]; then
  echo "ERROR: one or more input zips have an unexpected checksum." >&2
  echo "       Expected GP HSM Simulator v6.5.0.0 (u.trust-GP-HSM-Simulator_v6.5.0.0.zip)" >&2
  echo "       + QuantumProtect v1.5.0.0 (QuantumProtect-1.5.0.0-Evaluation.zip)." >&2
  exit 1
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

gp_fetch() {
  local pattern="$1"
  if ! unzip -o -q "$GP_HSM_ZIP" -d "$WORK/gp" "$pattern"; then
    return 1
  fi
  find "$WORK/gp" -type f -path "*$(basename "$pattern")" | head -1
}

log "extracting bootloader from $(basename "$GP_HSM_ZIP")"
BL="$(gp_fetch '*/Software/Linux/Simulator/sim5_linux/bin/bl_sim5')" || { echo "ERROR: bl_sim5 not found in $GP_HSM_ZIP" >&2; exit 1; }

log "extracting PKCS#11 client + admin tools from $(basename "$GP_HSM_ZIP")"
LIB="$(gp_fetch '*/Software/Linux/Crypto_APIs/PKCS11_R3/lib/libcs_pkcs11_R3.so')" || { echo "ERROR: libcs_pkcs11_R3.so not found" >&2; exit 1; }
LXI="$(gp_fetch '*/Software/Linux/Crypto_APIs/CXI/lib/libcxi.so')" || { echo "ERROR: libcxi.so not found" >&2; exit 1; }
CSADM="$(gp_fetch '*/Software/Linux/Administration/csadm')" || { echo "ERROR: csadm not found" >&2; exit 1; }
CXITOOL="$(gp_fetch '*/Software/Linux/Administration/cxitool')" || { echo "ERROR: cxitool not found" >&2; exit 1; }
P11TOOL2="$(gp_fetch '*/Software/Linux/Administration/p11tool2')" || { echo "ERROR: p11tool2 not found" >&2; exit 1; }
ADMIN_EC="$(gp_fetch '*/Software/Linux/Administration/key/ADMIN_EC.key')" || { echo "ERROR: ADMIN_EC.key not found" >&2; exit 1; }
ADMIN="$(gp_fetch '*/Software/Linux/Administration/key/ADMIN.key')" || { echo "ERROR: ADMIN.key not found" >&2; exit 1; }
ADMIN_SIM="$(gp_fetch '*/Software/Linux/Administration/key/ADMIN_SIM.key')" || { echo "ERROR: ADMIN_SIM.key not found" >&2; exit 1; }
GIAK="$(gp_fetch '*/Software/Linux/Administration/key/giak.pem')" || { echo "ERROR: giak.pem not found" >&2; exit 1; }

log "extracting cs_sim.ini + devices/ from $(basename "$QP_ZIP")"
unzip -o -q "$QP_ZIP" -d "$WORK/qp" '*/sim5_linux/bin/cs_sim.ini' '*/sim5_linux/devices/*' \
  || { echo "ERROR: sim5_linux/bin/cs_sim.ini or devices/ not found in $QP_ZIP" >&2; exit 1; }
SIMROOT="$(find "$WORK/qp" -type d -name sim5_linux | head -1)"
[[ -z "$SIMROOT" ]] && { echo "ERROR: sim5_linux/ not found in $QP_ZIP" >&2; exit 1; }
INI_SRC="$SIMROOT/bin/cs_sim.ini"
DEV_SRC="$SIMROOT/devices"
[[ -f "$INI_SRC" ]] || { echo "ERROR: cs_sim.ini not found" >&2; exit 1; }
[[ -d "$DEV_SRC" ]] || { echo "ERROR: devices/ not found" >&2; exit 1; }

log "writing Utimaco artifacts into $CTP_HSM"
mkdir -p "$CTP_HSM/sim/devices/SDRAM" "$CTP_HSM/keys"

cp "$BL"       "$CTP_HSM/sim/bl_sim5"
cp "$INI_SRC"  "$CTP_HSM/sim/cs_sim.ini"
cp -r "$DEV_SRC"/. "$CTP_HSM/sim/devices/"
cp "$LIB"      "$CTP_HSM/libcs_pkcs11_R3.so"
cp "$LXI"      "$CTP_HSM/libcxi.so"
cp "$CSADM"    "$CTP_HSM/csadm"
cp "$CXITOOL"  "$CTP_HSM/cxitool"
cp "$P11TOOL2" "$CTP_HSM/p11tool2"
cp "$ADMIN_EC" "$CTP_HSM/keys/ADMIN_EC.key"
cp "$ADMIN"    "$CTP_HSM/keys/ADMIN.key"
cp "$ADMIN_SIM" "$CTP_HSM/keys/ADMIN_SIM.key"
cp "$GIAK"     "$CTP_HSM/keys/giak.pem"
chmod +x "$CTP_HSM/csadm" "$CTP_HSM/cxitool" "$CTP_HSM/p11tool2" 2>/dev/null || true

log "checking checksums against validated v6.5.0.0 + v1.5.0.0 build"
FAILED=0
while read -r rel expected; do
  [[ -z "$rel" ]] && continue
  f="$CTP_HSM/$rel"
  if [[ ! -f "$f" ]]; then echo "FAIL: missing $rel" >&2; FAILED=1; continue; fi
  got="$(md5sum "$f" | awk '{print $1}')"
  if [[ "$got" == "$expected" ]]; then
    echo "  ok    $rel  $got"
  else
    echo "  FAIL  $rel  got=$got  expected=$expected" >&2; FAILED=1
  fi
done <<< "$EXPECT_SHA"

if [[ $FAILED -eq 1 ]]; then
  echo "ERROR: contents do not match the validated build." >&2
  echo "       Expected GP HSM Simulator v6.5.0.0 + QuantumProtect v1.5.0.0." >&2
  exit 1
fi

echo "OK: Utimaco artifacts written to $CTP_HSM"
