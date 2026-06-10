#!/usr/bin/env python3
import json
import re
import sys
import argparse
from pathlib import Path


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    text = re.sub(r"//.*", "", text)
    return text


def verified_loc(path: Path) -> int:
    inside = False
    count = 0
    for line in path.read_text(encoding="utf-8").splitlines():
        if "VKERNEL_VERIFIED_BEGIN" in line:
            inside = True
            continue
        if "VKERNEL_VERIFIED_END" in line:
            inside = False
            continue
        if inside:
            stripped = line.strip()
            if stripped and not stripped.startswith("/*") and not stripped.startswith("*"):
                count += 1
    return count


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


def split_first_top_level_arg(text: str) -> str:
    depth = 0
    in_string = False
    in_char = False
    escaped = False

    for index, ch in enumerate(text):
        if escaped:
            escaped = False
            continue
        if ch == "\\" and (in_string or in_char):
            escaped = True
            continue
        if ch == '"' and not in_char:
            in_string = not in_string
            continue
        if ch == "'" and not in_string:
            in_char = not in_char
            continue
        if in_string or in_char:
            continue
        if ch in "([{":
            depth += 1
            continue
        if ch in ")]}":
            depth -= 1
            continue
        if ch == "," and depth == 0:
            return text[:index].strip()

    return text.strip()


def assertion_expressions(text: str):
    search_from = 0
    while True:
        index = text.find("__CPROVER_assert", search_from)
        if index < 0:
            return
        paren_open = text.find("(", index)
        if paren_open < 0:
            return
        paren_close = matching(text, paren_open, "(", ")")
        yield split_first_top_level_arg(text[paren_open + 1:paren_close])
        search_from = paren_close + 1


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


def function_loc(text: str) -> int:
    stripped_text = strip_comments(text)
    return sum(1 for line in stripped_text.splitlines() if line.strip())


def verified_loc_from_linux_source(path: Path, symbols) -> int:
    text = path.read_text(encoding="utf-8", errors="replace")
    return sum(function_loc(find_function(text, symbol)) for symbol in symbols)


def specification_lines(paths):
    count = 0
    for path in paths:
        text = strip_comments(path.read_text(encoding="utf-8"))
        count += sum(1 for _ in assertion_expressions(text))
    return count


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("proof_json")
    parser.add_argument(
        "--linux-src",
        help="Linux source tree; counts real upstream symbols instead of fallback markers",
    )
    args = parser.parse_args()

    proof_path = Path(args.proof_json).resolve()
    root = proof_path.parents[4]
    proof = json.loads(proof_path.read_text(encoding="utf-8"))

    if args.linux_src:
        source = Path(args.linux_src).resolve() / proof["upstream"]["file"]
        loc = verified_loc_from_linux_source(source, proof["upstream"]["symbols"])
    else:
        fallback_source = proof.get("source_under_verification")
        if not fallback_source:
            print(
                f"{proof['name']} has no fallback source-under-verification; "
                "rerun with --linux-src",
                file=sys.stderr,
            )
            return 2
        source = root / fallback_source
        loc = verified_loc(source)
    spec_paths = [root / item for item in proof["spec_files"]]

    spec_lines = specification_lines(spec_paths)
    raw_units = loc * spec_lines
    units = raw_units / 1000.0

    report = {
        "proof": proof["name"],
        "verified_source_loc": loc,
        "specification_lines": spec_lines,
        "spec_metric_policy": "one complete __CPROVER_assert statement counts as one logical specification line; physical line breaks inside an assertion do not increase the count; wrappers never count; harness control flow, generated code, compatibility shims, and extraction glue are excluded",
        "raw_bounty_units": raw_units,
        "bounty_scale_divisor": 1000,
        "bounty_units": units,
        "source_under_verification": str(source),
        "spec_files": [str(path) for path in spec_paths],
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
