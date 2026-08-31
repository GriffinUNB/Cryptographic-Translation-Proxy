#!/bin/sh
set -e

SIM_BIN="/opt/utimaco/sim/bin"
SIM_DEV="/opt/utimaco/sim/devices"

if [ ! -f "$SIM_BIN/bl_sim5" ]; then
    echo "FATAL: bl_sim5 not found"
    exit 1
fi
if [ ! -f "$SIM_DEV/FLASHFILE" ]; then
    echo "FATAL: FLASHFILE not found"
    exit 1
fi

exec "$SIM_BIN/bl_sim5" -h -o -d "$SIM_DEV"