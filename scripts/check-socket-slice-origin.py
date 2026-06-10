#!/usr/bin/env python3
import argparse
import json
import re
import sys
from pathlib import Path


SYMBOLS = ["__sys_socket_create", "update_socket_protocol", "__sys_socket"]


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//.*", "", text)


def normalize(text: str) -> str:
    return re.sub(r"\s+", " ", strip_comments(text)).strip()


def matching(text: str, start: int, open_ch: str, close_ch: str) -> int:
    depth = 0
    i = start
    while i < len(text):
        ch = text[i]
        if ch == open_ch:
            depth += 1
        elif ch == close_ch:
            depth -= 1
            if depth == 0:
                return i
        i += 1
    raise ValueError(f"no matching {close_ch!r} after offset {start}")


def find_function(text: str, name: str) -> str:
    for match in re.finditer(rf"\b{re.escape(name)}\s*\(", text):
        paren_open = text.find("(", match.start())
        paren_close = matching(text, paren_open, "(", ")")
        after = paren_close + 1
        while after < len(text) and text[after].isspace():
            after += 1
        if after >= len(text) or text[after] != "{":
            continue
        line_start = text.rfind("\n", 0, match.start()) + 1
        brace_close = matching(text, after, "{", "}")
        return text[line_start:brace_close + 1]
    raise ValueError(f"function definition not found: {name}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--upstream", required=True, help="path to linux/net/socket.c")
    parser.add_argument(
        "--slice",
        default="kernel/net/socket_cbmc_slice.c",
        help="path to local verified socket slice",
    )
    args = parser.parse_args()

    upstream_path = Path(args.upstream).resolve()
    slice_path = Path(args.slice).resolve()

    upstream = upstream_path.read_text(encoding="utf-8")
    local = slice_path.read_text(encoding="utf-8")

    mismatches = []
    matched = []
    for symbol in SYMBOLS:
        upstream_fn = normalize(find_function(upstream, symbol))
        local_fn = normalize(find_function(local, symbol))
        if upstream_fn != local_fn:
            mismatches.append(symbol)
        else:
            matched.append(symbol)

    result = {
        "slice": str(slice_path),
        "upstream": str(upstream_path),
        "matched_symbols": matched,
        "mismatched_symbols": mismatches,
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if mismatches else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"slice origin check failed: {exc}", file=sys.stderr)
        raise SystemExit(2)

