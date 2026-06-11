#!/usr/bin/env python3
import argparse
from pathlib import Path


REPLACEMENTS = [
    ("__typeof_unqual__", "__typeof__"),
    ("__seg_gs", ""),
    ("__seg_fs", ""),
]


def lower_auto_type_declarations(text: str):
    count = 0
    out = []
    pos = 0

    while True:
        auto_pos = text.find("__auto_type", pos)
        if auto_pos == -1:
            out.append(text[pos:])
            break

        start = auto_pos
        const_prefix = ""
        const_start = text.rfind("const", pos, auto_pos)
        if const_start != -1 and text[const_start:auto_pos].strip() == "const":
            before = text[const_start - 1] if const_start > 0 else " "
            if not (before.isalnum() or before == "_"):
                start = const_start
                const_prefix = "const "

        i = auto_pos + len("__auto_type")
        while i < len(text) and text[i].isspace():
            i += 1
        name_start = i
        if i >= len(text) or not (text[i].isalpha() or text[i] == "_"):
            out.append(text[pos:auto_pos + len("__auto_type")])
            pos = auto_pos + len("__auto_type")
            continue
        i += 1
        while i < len(text) and (text[i].isalnum() or text[i] == "_"):
            i += 1
        name = text[name_start:i]
        while i < len(text) and text[i].isspace():
            i += 1
        if i >= len(text) or text[i] != "=":
            out.append(text[pos:auto_pos + len("__auto_type")])
            pos = auto_pos + len("__auto_type")
            continue
        i += 1
        expr_start = i

        paren = brace = bracket = 0
        quote = None
        escape = False
        while i < len(text):
            ch = text[i]
            if quote:
                if escape:
                    escape = False
                elif ch == "\\":
                    escape = True
                elif ch == quote:
                    quote = None
            else:
                if ch in {'"', "'"}:
                    quote = ch
                elif ch == "(":
                    paren += 1
                elif ch == ")":
                    paren -= 1
                elif ch == "{":
                    brace += 1
                elif ch == "}":
                    brace -= 1
                elif ch == "[":
                    bracket += 1
                elif ch == "]":
                    bracket -= 1
                elif ch == ";" and paren == 0 and brace == 0 and bracket == 0:
                    break
            i += 1

        if i >= len(text):
            out.append(text[pos:])
            break

        expr = text[expr_start:i].strip()
        out.append(text[pos:start])
        out.append(f"{const_prefix}typeof({expr}) {name} = {expr};")
        count += 1
        pos = i + 1

    return "".join(out), count


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input")
    parser.add_argument("output")
    parser.add_argument("--report", required=True)
    args = parser.parse_args()

    text = Path(args.input).read_text(encoding="utf-8", errors="replace")
    report_lines = []
    for old, new in REPLACEMENTS:
        count = text.count(old)
        if count:
            text = text.replace(old, new)
        report_lines.append(f"{old} -> {new}: {count}")
    text, auto_count = lower_auto_type_declarations(text)
    report_lines.append(f"__auto_type declarations lowered: {auto_count}")

    Path(args.output).write_text(text, encoding="utf-8")
    Path(args.report).write_text("\n".join(report_lines) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
