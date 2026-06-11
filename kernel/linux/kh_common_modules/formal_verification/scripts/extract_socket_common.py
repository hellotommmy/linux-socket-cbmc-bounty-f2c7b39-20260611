def matching(text: str, start: int, open_ch: str, close_ch: str) -> int:
    depth = 0
    quote = None
    escape = False
    i = start
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
            elif ch == open_ch:
                depth += 1
            elif ch == close_ch:
                depth -= 1
                if depth == 0:
                    return i
        i += 1
    raise ValueError(f"no matching {close_ch!r} after offset {start}")


def find_function(text: str, name: str) -> str:
    import re

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

