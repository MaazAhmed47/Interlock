#!/usr/bin/env python3
"""
Independent verifier for Interlock drift evidence records.

Recomputes the digest of a drift record from its canonical bytes and compares
it to the claimed digest from an evidenceRef. Deliberately self-contained
(stdlib only, no Interlock imports) so it proves client-recomputability: any
party can re-derive the digest without trusting Interlock or its code.

Canonicalization "json/jcs-rfc8785": UTF-8 JSON, keys sorted, separators
(",", ":"), non-ASCII unescaped. Drift records contain only strings and lists
of strings, for which this is byte-identical to RFC 8785 (JCS).

Usage:
  python scripts/verify_drift_evidence.py record.json --digest sha256:<hex>
  python scripts/verify_drift_evidence.py receipt.json        # pulls record +
                                                              # digest from a
                                                              # Security Receipt
  python scripts/verify_drift_evidence.py surface.json --surface \
      --digest sha256:<hex>                                   # verify a
                                                              # tool-surface
                                                              # snapshot

Exit code 0 = verified, 1 = mismatch or error.
"""

import argparse
import hashlib
import json
import sys


def canonical_bytes(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def digest_of(value):
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("path", help="JSON file: drift record, Security Receipt, or surface snapshot")
    parser.add_argument("--digest", help="Claimed digest (sha256:<hex>)")
    parser.add_argument(
        "--surface",
        action="store_true",
        help="Treat input as a tool-surface snapshot (canonical_json text or raw surface object)",
    )
    args = parser.parse_args()

    with open(args.path, "r", encoding="utf-8") as f:
        data = json.load(f)

    claimed = args.digest

    if args.surface:
        # A snapshot response carries canonical_json as text; hash its UTF-8
        # bytes directly. A raw surface object gets canonicalized first.
        if isinstance(data, dict) and "canonical_json" in data:
            computed = (
                "sha256:"
                + hashlib.sha256(data["canonical_json"].encode("utf-8")).hexdigest()
            )
            claimed = claimed or data.get("surface_hash")
        else:
            computed = digest_of(data)
    else:
        record = data
        # Accept a full Security Receipt and extract the drift evidence.
        if isinstance(data, dict) and "drift_evidence" in data:
            evidence = data.get("drift_evidence") or {}
            record = evidence.get("record")
            claimed = claimed or (evidence.get("evidence_ref") or {}).get("digest")
            if record is None:
                print("FAIL: receipt has no drift evidence record", file=sys.stderr)
                return 1
        computed = digest_of(record)

    if not claimed:
        print(f"computed: {computed}")
        print("No claimed digest provided (--digest); nothing to compare.", file=sys.stderr)
        return 1

    print(f"claimed:  {claimed}")
    print(f"computed: {computed}")
    if computed == claimed:
        print("VERIFIED: digest recomputed independently and matches.")
        return 0
    print("FAIL: recomputed digest does not match claim.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
