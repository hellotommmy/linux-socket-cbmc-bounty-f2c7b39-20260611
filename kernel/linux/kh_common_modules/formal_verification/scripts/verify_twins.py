#!/usr/bin/env python3
import argparse
import hashlib
import json
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--linux-src",
        required=True,
        help="Linux source tree containing the production files",
    )
    parser.add_argument(
        "--manifest",
        default="twins/manifest.json",
        help="Twin manifest relative to this formal_verification directory",
    )
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    linux_src = Path(args.linux_src).resolve()
    manifest_path = (root / args.manifest).resolve()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    failures = []
    for item in manifest["twins"]:
        production = linux_src / item["production"]
        twin = root / item["twin"]
        if not production.is_file():
            failures.append(f"missing production file: {production}")
            continue
        if not twin.is_file():
            failures.append(f"missing twin file: {twin}")
            continue
        production_bytes = production.read_bytes()
        twin_bytes = twin.read_bytes()
        production_hash = hashlib.sha256(production_bytes).hexdigest()
        twin_hash = hashlib.sha256(twin_bytes).hexdigest()
        if production_bytes != twin_bytes:
            failures.append(
                "twin drift: "
                f"{item['twin']} != {item['production']} "
                f"(production sha256={production_hash}, twin sha256={twin_hash})"
            )
            continue
        print(
            json.dumps(
                {
                    "production": str(production),
                    "twin": str(twin),
                    "sha256": production_hash,
                    "bytes": len(production_bytes),
                    "status": "byte-identical",
                },
                sort_keys=True,
            )
        )

    if failures:
        for failure in failures:
            print(failure, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
