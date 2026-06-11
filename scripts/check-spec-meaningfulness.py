#!/usr/bin/env python3
import argparse
import importlib.util
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path


def load_metrics_module():
    metrics_path = Path(__file__).with_name("count-proof-metrics.py")
    spec = importlib.util.spec_from_file_location("count_proof_metrics", metrics_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {metrics_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


METRICS = load_metrics_module()


@dataclass
class Call:
    path: Path
    line: int
    kind: str
    expr: str
    message: str


OUTCOME_TOKENS = (
    "result",
    "errno",
    "ret",
    "calls",
    "_calls",
    "live",
    "alloc",
    "free",
    "fput",
    "fd",
    "flags",
    "optlen",
    "optval",
    "dispatch",
    "security",
    "sock",
    "file",
    "socket",
    "proto",
)


def split_top_level_args(text: str):
    args = []
    depth = 0
    in_string = False
    in_char = False
    escaped = False
    start = 0

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
            args.append(text[start:index].strip())
            start = index + 1

    args.append(text[start:].strip())
    return args


def line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def unquote_message(arg: str) -> str:
    match = re.fullmatch(r'"(.*)"', arg.strip(), flags=re.S)
    if not match:
        return ""
    return bytes(match.group(1), "utf-8").decode("unicode_escape", errors="ignore")


def iter_calls(path: Path, kind: str):
    text = METRICS.strip_comments(path.read_text(encoding="utf-8"))
    search_from = 0
    needle = f"__CPROVER_{kind}"
    while True:
        index = text.find(needle, search_from)
        if index < 0:
            return
        paren_open = text.find("(", index)
        if paren_open < 0:
            return
        paren_close = METRICS.matching(text, paren_open, "(", ")")
        args = split_top_level_args(text[paren_open + 1 : paren_close])
        expr = args[0] if args else ""
        message = unquote_message(args[1]) if len(args) > 1 else ""
        yield Call(path, line_number(text, index), kind, expr, message)
        search_from = paren_close + 1


def normalize_expr(expr: str) -> str:
    expr = re.sub(r"\s+", "", expr)
    changed = True
    while changed and expr.startswith("(") and expr.endswith(")"):
        changed = False
        try:
            if METRICS.matching(expr, 0, "(", ")") == len(expr) - 1:
                expr = expr[1:-1]
                changed = True
        except ValueError:
            break
    return expr


def is_literal_true(expr: str) -> bool:
    normalized = normalize_expr(expr).lower()
    return normalized in {"1", "true", "(_bool)1", "!0"}


def is_literal_false(expr: str) -> bool:
    normalized = normalize_expr(expr).lower()
    return normalized in {"0", "false", "(_bool)0", "!1"}


def is_self_comparison(expr: str) -> bool:
    normalized = normalize_expr(expr)
    for op in ("==", "<=", ">="):
        if op not in normalized:
            continue
        left, right = normalized.split(op, 1)
        if left and left == right:
            return True
    return False


def is_excluded_middle(expr: str) -> bool:
    normalized = normalize_expr(expr)
    for op in ("||", "&&"):
        if op not in normalized:
            continue
        left, right = normalized.split(op, 1)
        if op == "||" and ((left == f"!{right}") or (right == f"!{left}")):
            return True
        if op == "&&" and left == right:
            return True
    return False


def has_meaningful_token(call: Call) -> bool:
    blob = f"{call.expr} {call.message}".lower()
    return any(token in blob for token in OUTCOME_TOKENS)


def check_call(call: Call):
    problems = []
    where = f"{call.path}:{call.line}"

    if call.kind == "assume" and is_literal_false(call.expr):
        problems.append(f"{where}: impossible __CPROVER_assume removes proof paths")

    if call.kind != "assert":
        return problems

    if is_literal_true(call.expr):
        problems.append(f"{where}: constant-true assertion is not a specification")
    if is_self_comparison(call.expr):
        problems.append(f"{where}: self-comparison assertion is tautological")
    if is_excluded_middle(call.expr):
        problems.append(f"{where}: tautological or duplicate boolean assertion")
    if is_literal_false(call.expr):
        allowed = ("unreachable", "returns only modeled", "impossible")
        if not any(token in call.message.lower() for token in allowed):
            problems.append(
                f"{where}: literal-false assertion needs an explicit unreachable-state message"
            )

    return problems


def check_proof(root: Path, proof_path: Path):
    proof = json.loads(proof_path.read_text(encoding="utf-8"))
    calls = []
    for item in proof["spec_files"]:
        spec_path = root / item
        calls.extend(iter_calls(spec_path, "assert"))
        calls.extend(iter_calls(spec_path, "assume"))

    problems = []
    assertions = [call for call in calls if call.kind == "assert"]
    if not assertions:
        problems.append(f"{proof_path}: proof has no explicit assertions")
    if not any(has_meaningful_token(call) for call in assertions):
        problems.append(
            f"{proof_path}: no assertion mentions outcome, dispatch, flags, pointers, or lifetime"
        )

    for call in calls:
        problems.extend(check_call(call))
    return problems


def default_proofs(root: Path):
    return sorted((root / "verification/cbmc/proofs").glob("*/proof.json"))


def repo_root() -> Path:
    cwd = Path.cwd().resolve()
    if (cwd / "verification/cbmc/proofs").is_dir():
        return cwd
    return Path(__file__).resolve().parents[1]


def resolve_proof_arg(root: Path, arg: str) -> Path:
    path = Path(arg)
    if path.is_absolute():
        return path
    cwd_candidate = (Path.cwd() / path).resolve()
    if cwd_candidate.exists():
        return cwd_candidate
    return (root / path).resolve()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("proof_json", nargs="*")
    args = parser.parse_args()

    root = repo_root()
    proof_paths = [resolve_proof_arg(root, item) for item in args.proof_json]
    if not proof_paths:
        proof_paths = default_proofs(root)

    problems = []
    for proof_path in proof_paths:
        problems.extend(check_proof(root, proof_path))

    if problems:
        print("spec meaningfulness check failed:", file=sys.stderr)
        for problem in problems:
            print(f"- {problem}", file=sys.stderr)
        return 1

    print(f"spec meaningfulness check passed for {len(proof_paths)} proof(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
