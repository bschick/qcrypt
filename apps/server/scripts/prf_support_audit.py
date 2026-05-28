#!/usr/bin/env python3
"""One-shot audit of registered passkeys' likely WebAuthn PRF support.

Designed for AWS CloudShell — depends only on boto3, which is preinstalled.

Run:
    AWS_REGION=us-east-1 python3 prf_support_audit.py

See the TypeScript version (prf-support-audit.ts) for design notes on what
the server stores and which categories are AMBIGUOUS from server data alone.
"""

import os
import re
import sys
from collections import defaultdict

import boto3

ZERO_AAGUID = "00000000-0000-0000-0000-000000000000"

# Known test/emulator AAGUIDs — not real authenticators. Tagged as TEST so
# they're excluded from the real-user denominator in the summary.
TEST_AAGUIDS = {
    "4e49442d-4155-5448-2d33-313431353932": "nid-webauthn-emulator (test/pentest)",
    "01020304-0506-0708-0102-030405060708": "sequential-hex stub (test)",
}

# (name regex, classifier). First match wins.
# classifier returns (verdict, note).
SUPPORT_RULES = [
    (re.compile(r"samsung", re.I),
     lambda *_: ("LIKELY_YES", "Yes since mid-2024.")),
    (
        re.compile(r"apple|icloud", re.I),
        lambda device_type, backed_up: (
            ("AMBIGUOUS",
             "Yes on Safari/Chrome/Edge on macOS/iOS/Windows; "
             "No on macOS Firefox (no extension).")
            if backed_up is True else
            ("LIKELY_YES",
             "Platform-bound (Secure Enclave) — Yes in every browser that drives it.")
        ),
    ),
    (
        re.compile(r"windows hello|microsoft", re.I),
        lambda device_type, backed_up: (
            ("LIKELY_NO",
             "Microsoft Account synced passkeys do not yet support PRF.")
            if backed_up is True else
            ("AMBIGUOUS",
             "Local Windows Hello — Yes only on Win11 builds ~26200+ (early 2026). "
             "Server cannot tell build.")
        ),
    ),
    (re.compile(r"google|chrom", re.I),
     lambda *_: ("LIKELY_YES",
                 "Yes on all platforms.")),
    (re.compile(r"1password", re.I),
     lambda *_: ("LIKELY_YES", "Yes in stable releases.")),
    (re.compile(r"dashlane", re.I),
     lambda *_: ("LIKELY_YES", "Yes in all browsers.")),
    (re.compile(r"keeper", re.I),
     lambda *_: ("LIKELY_YES", "Yes since extension v17.8.0 (April 2026).")),
    (re.compile(r"protonpass|proton pass", re.I),
     lambda *_: ("LIKELY_YES", "Yes since ~Nov 2025 (undocumented).")),
    (re.compile(r"bitwarden", re.I),
     lambda *_: ("LIKELY_NO",
                 "Uses PRF internally to unlock, does not pass it through.")),
    (re.compile(r"lastpass", re.I),
     lambda *_: ("LIKELY_NO", "No support announced.")),
    (re.compile(r"nordpass", re.I),
     lambda *_: ("LIKELY_NO", "No support announced.")),
    (re.compile(r"yubikey|yubico", re.I),
     lambda *_: ("AMBIGUOUS",
                 "Yes on macOS/Windows/Linux (firmware 5.4.3+); "
                 "partially broken on iOS (WebKit bug 311099).")),
    (re.compile(r"solokey", re.I),
     lambda *_: ("AMBIGUOUS",
                 "Yes on macOS/Windows/Linux (Solo V2+); assumed broken on iOS.")),
]


def classify(name, device_type, backed_up):
    for pattern, fn in SUPPORT_RULES:
        if pattern.search(name):
            return fn(device_type, backed_up)
    return ("UNKNOWN", "No support data for this authenticator family.")


def scan_authenticators(dynamodb):
    paginator = dynamodb.get_paginator("scan")
    pages = paginator.paginate(
        TableName="Authenticators",
        ProjectionExpression="aaguid, credentialDeviceType, credentialBackedUp",
    )
    results = []
    for page in pages:
        for item in page.get("Items", []):
            results.append({
                "aaguid": item.get("aaguid", {}).get("S"),
                "credentialDeviceType": item.get("credentialDeviceType", {}).get("S", "unknown"),
                "credentialBackedUp": item.get("credentialBackedUp", {}).get("BOOL"),
            })
    return results


def resolve_aaguid_names(dynamodb, aaguids):
    # The AAGUIDs table is stored under ElectroDB's composite-key scheme
    # (partition key is a formatted string, not the raw aaguid attribute), so
    # BatchGetItem would need us to reproduce that format. Easier and cheap:
    # scan the whole lookup table once and build a local map.
    distinct = {value for value in aaguids if value and value != ZERO_AAGUID}
    if not distinct:
        return {}
    paginator = dynamodb.get_paginator("scan")
    pages = paginator.paginate(
        TableName="AAGUIDs",
        ProjectionExpression="aaguid, #name",
        ExpressionAttributeNames={"#name": "name"},
    )
    names = {}
    for page in pages:
        for item in page.get("Items", []):
            aaguid = item.get("aaguid", {}).get("S")
            name = item.get("name", {}).get("S")
            if aaguid in distinct and name is not None:
                names[aaguid] = name
    return names


def main():
    region = os.environ.get("AWS_REGION", "us-east-1")
    dynamodb = boto3.client("dynamodb", region_name=region)

    authenticators = scan_authenticators(dynamodb)
    print(f"scanned {len(authenticators)} authenticators", file=sys.stderr)

    aaguid_set = {row["aaguid"] for row in authenticators if row["aaguid"]}
    names = resolve_aaguid_names(dynamodb, aaguid_set)

    groups = {}
    for row in authenticators:
        raw_aaguid = row["aaguid"] or "(missing)"
        if raw_aaguid in TEST_AAGUIDS:
            name = TEST_AAGUIDS[raw_aaguid]
            verdict, note = "TEST", "Not a real authenticator; excluded from real-user totals."
        elif raw_aaguid == ZERO_AAGUID:
            name = "(zero AAGUID — anonymous authenticator)"
            verdict, note = classify(name, row["credentialDeviceType"], row["credentialBackedUp"])
        elif raw_aaguid == "(missing)":
            name = "(no AAGUID stored)"
            verdict, note = classify(name, row["credentialDeviceType"], row["credentialBackedUp"])
        else:
            name = names.get(raw_aaguid, f"(unmapped AAGUID {raw_aaguid})")
            verdict, note = classify(name, row["credentialDeviceType"], row["credentialBackedUp"])
        device_type = row["credentialDeviceType"]
        backed_up = row["credentialBackedUp"]
        key = (raw_aaguid, name, device_type, backed_up)
        if key in groups:
            groups[key]["count"] += 1
        else:
            groups[key] = {
                "aaguid": raw_aaguid, "name": name, "deviceType": device_type,
                "backedUp": backed_up, "count": 1, "verdict": verdict, "note": note,
            }

    sorted_groups = sorted(groups.values(), key=lambda group: group["count"], reverse=True)

    totals = defaultdict(int)
    for group in sorted_groups:
        totals[group["verdict"]] += group["count"]

    print("\n=== Per-group breakdown ===")
    print("count\tverdict     \tdeviceType    \tbackedUp\tname (note)")
    for group in sorted_groups:
        backed_up_str = "unknown" if group["backedUp"] is None else str(group["backedUp"])
        print(f'{group["count"]}\t{group["verdict"]:<12}\t{group["deviceType"]:<14}\t'
              f'{backed_up_str}\t{group["name"]} — {group["note"]}')

    total = len(authenticators)
    test_count = totals["TEST"]
    real_total = total - test_count
    def pct(count, denom):
        return f'{(count / denom * 100):.1f}%' if denom else '0%'

    print("\n=== Summary ===")
    print(f"Total records:       {total}")
    print(f"Test/emulator:       {test_count} (excluded below)")
    print(f"Real-user passkeys:  {real_total}")
    print()
    for verdict in ("LIKELY_YES", "LIKELY_NO", "AMBIGUOUS", "UNKNOWN"):
        print(f"{verdict + ':':<19}{totals[verdict]:>6} ({pct(totals[verdict], real_total)})")
    print("\nNote: AMBIGUOUS groups cannot be resolved further without per-user OS/browser data,")
    print("      which the server does not record.")


if __name__ == "__main__":
    main()
