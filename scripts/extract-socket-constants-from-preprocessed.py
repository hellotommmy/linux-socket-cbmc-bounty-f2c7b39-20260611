#!/usr/bin/env python3
import argparse
import re
import sys
from pathlib import Path


def parse_c_int(token: str) -> int:
    token = token.strip()
    token = re.sub(r"(?i)(ul|lu|ull|llu|u|l)+$", "", token)
    if re.fullmatch(r"0[0-7]+", token):
        return int(token, 8)
    return int(token, 0)


def parse_c_or_expression(expr: str) -> int:
    value = 0
    for part in expr.split("|"):
        value |= parse_c_int(part)
    return value


def find_required(pattern: str, text: str, label: str):
    match = re.search(pattern, text, flags=re.S)
    if not match:
        raise ValueError(f"could not extract {label}")
    return match


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("socket_i", help="Kbuild-generated net/socket.i")
    parser.add_argument("output", help="generated constants header")
    args = parser.parse_args()

    text = Path(args.socket_i).read_text(encoding="utf-8", errors="replace")
    compact = re.sub(r"\s+", " ", text)

    invalid = find_required(
        r"if\s*\(\s*\(\s*type\s*&\s*~\s*([0-9A-Fa-fxULul]+)\s*\)\s*&\s*~\s*\(\s*([0-9A-Fa-fxULul]+)\s*\|\s*([0-9A-Fa-fxULul]+)\s*\)\s*\)",
        compact,
        "__sys_socket_create flag mask",
    )
    fd_mask = find_required(
        r"return\s+sock_map_fd\s*\(\s*sock\s*,\s*flags\s*&\s*\(\s*([0-9A-Fa-fxULul]+)\s*\|\s*([0-9A-Fa-fxULul]+)\s*\)\s*\)",
        compact,
        "__sys_socket fd flag mask",
    )
    nonblock = find_required(
        r"if\s*\(\s*([0-9A-Fa-fxULul]+)\s*!=\s*([0-9A-Fa-fxULul]+)\s*&&\s*\(\s*flags\s*&\s*([0-9A-Fa-fxULul]+)\s*\)\s*\)",
        compact,
        "__sys_socket nonblock normalization",
    )
    invalid_errno = find_required(
        r"if\s*\(\s*\(\s*type\s*&\s*~\s*[0-9A-Fa-fxULul]+\s*\)\s*&\s*~\s*\(\s*[0-9A-Fa-fxULul]+\s*\|\s*[0-9A-Fa-fxULul]+\s*\)\s*\)"
        r"\s*return\s+ERR_PTR\s*\(\s*-\s*([0-9A-Fa-fxULul]+)\s*\)",
        compact,
        "EINVAL in __sys_socket_create invalid flags path",
    )
    sock_packet = find_required(
        r"\bSOCK_PACKET\s*=\s*([0-9A-Fa-fxULul]+)\s*,",
        compact,
        "SOCK_PACKET enum value",
    )
    msg_cmsg_compat = find_required(
        r"if\s*\(\s*\(\s*([0-9A-Fa-fxULul]+)\s*&\s*flags\s*\)\s*&&\s*ctl_len\s*\)",
        compact,
        "MSG_CMSG_COMPAT in ____sys_sendmsg",
    )
    internal_sendmsg_flags = find_required(
        r"flags\s*&=\s*~\s*\(\s*([0-9A-Fa-fxULul\s|]+?)\s*\)\s*;\s*msg_sys->msg_flags\s*=\s*flags\s*;",
        compact,
        "MSG_INTERNAL_SENDMSG_FLAGS in ____sys_sendmsg",
    )
    msg_dontwait = find_required(
        r"if\s*\(\s*sock->file->f_flags\s*&\s*[0-9A-Fa-fxULul]+\s*\)\s*msg_sys->msg_flags\s*\|=\s*([0-9A-Fa-fxULul]+)\s*;",
        compact,
        "MSG_DONTWAIT in ____sys_sendmsg",
    )
    enobufs = find_required(
        r"err\s*=\s*-\s*([0-9A-Fa-fxULul]+)\s*;\s*if\s*\(\s*msg_sys->msg_controllen\s*>\s*\(\(int\)\(~0U\s*>>\s*1\)\)\s*\)",
        compact,
        "ENOBUFS in ____sys_sendmsg",
    )

    sock_type_mask = parse_c_int(invalid.group(1))
    sock_cloexec = parse_c_int(invalid.group(2))
    sock_nonblock = parse_c_int(invalid.group(3))
    o_cloexec = parse_c_int(fd_mask.group(1))
    o_nonblock = parse_c_int(fd_mask.group(2))

    normalized_sock_nonblock = parse_c_int(nonblock.group(3))
    if normalized_sock_nonblock != sock_nonblock:
        raise ValueError("SOCK_NONBLOCK mismatch between validation and normalization")

    header = f"""/* Generated from {Path(args.socket_i).resolve()} */
#ifndef VKERNEL_SOCKET_CONTRACTS_KERNEL_CONSTANTS_H
#define VKERNEL_SOCKET_CONTRACTS_KERNEL_CONSTANTS_H

#define VKERNEL_SOCK_TYPE_MASK {sock_type_mask}
#define VKERNEL_SOCK_CLOEXEC {sock_cloexec}
#define VKERNEL_SOCK_NONBLOCK {sock_nonblock}
#define VKERNEL_O_CLOEXEC {o_cloexec}
#define VKERNEL_O_NONBLOCK {o_nonblock}
#define VKERNEL_SOCK_PACKET {parse_c_int(sock_packet.group(1))}
#define VKERNEL_EINVAL {parse_c_int(invalid_errno.group(1))}
#define VKERNEL_ENOMEM 12
#define VKERNEL_EAFNOSUPPORT 97
#define VKERNEL_EPROTONOSUPPORT 93
#define VKERNEL_EFAULT 14
#define VKERNEL_EMFILE 24
#define VKERNEL_EPERM 1
#define VKERNEL_ENOBUFS {parse_c_int(enobufs.group(1))}
#define VKERNEL_MSG_CMSG_COMPAT {parse_c_int(msg_cmsg_compat.group(1))}U
#define VKERNEL_MSG_INTERNAL_SENDMSG_FLAGS {parse_c_or_expression(internal_sendmsg_flags.group(1))}U
#define VKERNEL_MSG_DONTWAIT {parse_c_int(msg_dontwait.group(1))}U
#define VKERNEL_INT_MAX ((int)(~0U >> 1))

#endif
"""
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(header, encoding="utf-8")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"extract socket constants failed: {exc}", file=sys.stderr)
        raise SystemExit(2)
