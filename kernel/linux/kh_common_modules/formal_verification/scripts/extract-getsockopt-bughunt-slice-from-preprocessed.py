#!/usr/bin/env python3
import argparse
import sys
from pathlib import Path

from extract_socket_common import find_function


def is_kernel_sockptr_warning(line: str) -> bool:
    return (
        "if (" in line
        and "optval" in line
        and "optlen" in line
        and "is_kernel" in line
        and (
            "__ret_warn_on" in line
            or "__builtin_expect" in line
            or "WARN" in line
            or "unlikely" in line
        )
    )


def rewrite_getsockopt_body(body: str) -> str:
    rewritten = []
    read_once_rewrite = 0
    warn_rewrite = 0
    bpf_rewrite = 0
    skipping_warn = False
    skipping_bpf_semicolon = False

    for line in body.splitlines():
        stripped = line.strip()

        if skipping_warn:
            if "return -95;" in line:
                rewritten.append("\t\t\treturn -VKERNEL_EOPNOTSUPP;")
                skipping_warn = False
            continue

        if skipping_bpf_semicolon:
            if stripped == ";":
                skipping_bpf_semicolon = False
            continue

        if "ops = ({ do {" in line and "__compiletime_assert_" in line and "sock->ops" in line:
            rewritten.append("\tops = sock->ops;")
            read_once_rewrite += 1
            continue

        if is_kernel_sockptr_warning(line):
            rewritten.append("\t\tif (optval.is_kernel || optlen.is_kernel)")
            warn_rewrite += 1
            skipping_warn = True
            continue

        if stripped == "err = ({ err; })":
            rewritten.append("\t\terr = err;")
            bpf_rewrite += 1
            skipping_bpf_semicolon = True
            continue

        rewritten.append(line)

    if skipping_warn or skipping_bpf_semicolon:
        raise ValueError("unterminated getsockopt rewrite skip")
    if read_once_rewrite != 1 or warn_rewrite not in (0, 1) or bpf_rewrite != 1:
        raise ValueError(
            "unexpected getsockopt rewrite counts: "
            f"read_once_rewrite={read_once_rewrite}, "
            f"warn_rewrite={warn_rewrite}, bpf_rewrite={bpf_rewrite}"
        )
    return "\n".join(rewritten) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("preprocessed")
    parser.add_argument("output")
    args = parser.parse_args()

    text = Path(args.preprocessed).read_text(encoding="utf-8", errors="replace")
    body = rewrite_getsockopt_body(find_function(text, "do_sock_getsockopt"))

    prelude = """/* Generated from Kbuild net/socket.i by extract-getsockopt-bughunt-slice-from-preprocessed.py. */
#include "socket_contracts_kernel_constants.h"

typedef _Bool bool;
typedef unsigned long size_t;

#ifndef true
#define true ((_Bool)1)
#endif
#ifndef false
#define false ((_Bool)0)
#endif

typedef struct {
\tunion {
\t\tvoid *kernel;
\t\tvoid *user;
\t};
\tbool is_kernel : 1;
} sockptr_t;

struct sock {
\tint model_id;
};

struct socket;

struct proto_ops {
\tint (*getsockopt)(struct socket *sock, int level, int optname,
\t\t\t\t  char *optval, int *optlen);
};

struct socket {
\tstruct sock *sk;
\tconst struct proto_ops *ops;
\tint model_id;
};

int security_socket_getsockopt(struct socket *sock, int level, int optname);
int copy_from_sockptr(void *dst, sockptr_t src, size_t size);
int sk_getsockopt(struct sock *sk, int level, int optname,
\t\t\t  sockptr_t optval, sockptr_t optlen);
"""

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(prelude + "\n\n" + body, encoding="utf-8")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"extract getsockopt bughunt slice failed: {exc}", file=sys.stderr)
        raise SystemExit(2)
