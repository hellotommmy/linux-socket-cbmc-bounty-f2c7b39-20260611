#!/usr/bin/env python3
import argparse
import sys
from pathlib import Path

from extract_socket_common import find_function


def rewrite_setsockopt_body(body: str) -> str:
    rewritten = []
    read_once_rewrite = 0
    bpf_rewrite = 0
    skipping_bpf_semicolon = False

    for line in body.splitlines():
        stripped = line.strip()

        if skipping_bpf_semicolon:
            if stripped == ";":
                skipping_bpf_semicolon = False
            continue

        if "ops = ({ do {" in line and "__compiletime_assert_" in line and "sock->ops" in line:
            rewritten.append("\tops = sock->ops;")
            read_once_rewrite += 1
            continue

        if stripped == "err = ({ 0; })":
            rewritten.append("\t\terr = 0;")
            bpf_rewrite += 1
            skipping_bpf_semicolon = True
            continue

        rewritten.append(line)

    if skipping_bpf_semicolon:
        raise ValueError("unterminated setsockopt BPF rewrite skip")
    if read_once_rewrite != 1 or bpf_rewrite != 1:
        raise ValueError(
            "unexpected setsockopt rewrite counts: "
            f"read_once_rewrite={read_once_rewrite}, bpf_rewrite={bpf_rewrite}"
        )
    return "\n".join(rewritten) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("preprocessed")
    parser.add_argument("output")
    args = parser.parse_args()

    text = Path(args.preprocessed).read_text(encoding="utf-8", errors="replace")
    body = rewrite_setsockopt_body(find_function(text, "do_sock_setsockopt"))

    prelude = """/* Generated from Kbuild net/socket.i by extract-setsockopt-bughunt-slice-from-preprocessed.py. */
#include "socket_contracts_kernel_constants.h"

typedef _Bool bool;

#ifndef true
#define true ((_Bool)1)
#endif
#ifndef false
#define false ((_Bool)0)
#endif
#ifndef NULL
#define NULL ((void *)0)
#endif

typedef struct {
\tunion {
\t\tvoid *kernel;
\t\tvoid *user;
\t};
\tbool is_kernel : 1;
} sockptr_t;

static sockptr_t KERNEL_SOCKPTR(void *p)
{
\tsockptr_t ptr;

\tptr.kernel = p;
\tptr.is_kernel = true;
\treturn ptr;
}

struct sock {
\tint model_id;
};

struct socket;

struct proto_ops {
\tint (*setsockopt)(struct socket *sock, int level, int optname,
\t\t\t\t  sockptr_t optval, int optlen);
};

struct socket {
\tstruct sock *sk;
\tconst struct proto_ops *ops;
\tunsigned long flags;
\tint model_id;
};

int security_socket_setsockopt(struct socket *sock, int level, int optname);
bool sock_use_custom_sol_socket(const struct socket *sock);
int sock_setsockopt(struct socket *sock, int level, int optname,
\t\t\t    sockptr_t optval, int optlen);
void kfree(const void *ptr);
"""

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(prelude + "\n\n" + body, encoding="utf-8")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"extract setsockopt bughunt slice failed: {exc}", file=sys.stderr)
        raise SystemExit(2)
