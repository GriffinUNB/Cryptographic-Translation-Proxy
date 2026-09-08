#!/usr/bin/env python3
"""Parse a Utimaco cs_pkcs11_R3.log TRACE log and emit per-call durations.

The Utimaco PKCS#11 middleware writes timestamped enter/leave trace lines when
``Logging = 4`` is set in ``cs_pkcs11_R3.cfg``::

    31.07.2026 20:15:20.038 | [00056357:00056361] C_GenerateKeyPair | T: enter ...
    31.07.2026 20:15:20.040 | [00056357:00056361] C_GenerateKeyPair | T: leave ...

This script pairs enter/leave lines per thread and prints ``FUNC  duration_ms``
for every matched call. Output is tab-separated and stable, so the shell
collector can grep for a specific function (e.g. ``C_GenerateKeyPair``) and
pipe the durations straight into a ``*_ms.txt`` timing file.

Usage:
    python3 parse_cs_pkcs11_log.py <logfile> [function_filter]

Examples:
    # All calls, one row per call
    python3 parse_cs_pkcs11_log.py /tmp/cs_pkcs11_R3.log

    # Only C_GenerateKeyPair durations
    python3 parse_cs_pkcs11_log.py /tmp/cs_pkcs11_R3.log C_GenerateKeyPair

    # C_GenerateKeyPair + C_Login into separate files
    python3 parse_cs_pkcs11_log.py log.log C_GenerateKeyPair > fw_keygen_ms.txt
    python3 parse_cs_pkcs11_log.py log.log C_Login          > c_login_ms.txt
"""
import re
import sys
from collections import defaultdict
from datetime import datetime

LINE_RE = re.compile(
    r"(\d{2}\.\d{2}\.\d{4} \d{2}:\d{2}:\d{2}\.\d{3}) \| "
    r"\[([^\]]+)\] (\S+).*\| T: (enter|leave)"
)


def parse(path):
    """Return list of (func, duration_ms) for every matched enter/leave pair."""
    events = []
    with open(path) as f:
        for line in f:
            m = LINE_RE.match(line.rstrip("\n"))
            if not m:
                continue
            ts_str, _tid, func, action = m.groups()
            ts = datetime.strptime(ts_str, "%d.%m.%Y %H:%M:%S.%f")
            events.append((ts, func, action))

    stack = defaultdict(list)
    out = []
    for ts, func, action in events:
        if action == "enter":
            stack[func].append(ts)
        elif action == "leave" and stack[func]:
            ent = stack[func].pop()
            dur_ms = (ts - ent).total_seconds() * 1000.0
            out.append((func, dur_ms))
    return out


def main():
    if len(sys.argv) < 2:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    path = sys.argv[1]
    flt = sys.argv[2] if len(sys.argv) > 2 else None
    for func, dur in parse(path):
        if flt and func != flt:
            continue
        print(f"{func}\t{dur:.3f}")


if __name__ == "__main__":
    main()
