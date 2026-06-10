#!/usr/bin/env python3
import argparse
import re
import sys
from pathlib import Path

from extract_socket_common import find_function


def rewrite_sendmsg_body(body: str) -> str:
    rewritten = []
    build_bug_on = 0
    gfp_rewrite = 0
    internal_flags_rewrite = 0

    for line in body.splitlines():
        if "__compiletime_assert_" in line and "BUILD_BUG_ON failed:" in line:
            rewritten.append("\t(void)0;")
            build_bug_on += 1
            continue
        if "sock_kmalloc(sock->sk, ctl_len," in line:
            rewritten.append("\t\t\tctl_buf = sock_kmalloc(sock->sk, ctl_len, 0);")
            gfp_rewrite += 1
            continue
        if "flags &= ~(" in line and "0x8000000" in line and "0x10000" in line:
            rewritten.append("\tflags &= ~VKERNEL_MSG_INTERNAL_SENDMSG_FLAGS;")
            internal_flags_rewrite += 1
            continue
        rewritten.append(line)

    if build_bug_on != 1 or gfp_rewrite != 1 or internal_flags_rewrite != 1:
        raise ValueError(
            "unexpected sendmsg rewrite counts: "
            f"build_bug_on={build_bug_on}, gfp_rewrite={gfp_rewrite}, "
            f"internal_flags_rewrite={internal_flags_rewrite}"
        )
    return "\n".join(rewritten) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("preprocessed")
    parser.add_argument("output")
    args = parser.parse_args()

    text = Path(args.preprocessed).read_text(encoding="utf-8", errors="replace")
    body = rewrite_sendmsg_body(find_function(text, "____sys_sendmsg"))

    prelude = """/* Generated from Kbuild net/socket.i by extract-sendmsg-control-bughunt-slice-from-preprocessed.py. */
#include "socket_contracts_kernel_constants.h"

typedef _Bool bool;
typedef long ssize_t;
typedef unsigned long size_t;
typedef unsigned long __kernel_size_t;
typedef unsigned int gfp_t;

#ifndef true
#define true ((_Bool)1)
#endif
#ifndef false
#define false ((_Bool)0)
#endif

struct cmsghdr {
\t__kernel_size_t cmsg_len;
\tint cmsg_level;
\tint cmsg_type;
};

struct sockaddr_storage {
\tunsigned char bytes[128];
};

struct sock {
\tint model_id;
};

struct file {
\tint f_flags;
};

struct socket {
\tstruct sock *sk;
\tstruct file *file;
};

struct msghdr {
\tvoid *msg_name;
\tint msg_namelen;
\tint msg_inq;
\tunion {
\t\tvoid *msg_control;
\t\tvoid *msg_control_user;
\t};
\tbool msg_control_is_user;
\tbool msg_get_inq;
\tunsigned int msg_flags;
\t__kernel_size_t msg_controllen;
\tvoid *msg_iocb;
\tvoid *msg_ubuf;
};

struct used_address {
\tstruct sockaddr_storage name;
\tunsigned int name_len;
};

int cmsghdr_from_user_compat_to_kern(struct msghdr *kmsg, struct sock *sk,
\t\t\t\t\t     unsigned char *stackbuf, int stackbuf_size);
void *sock_kmalloc(struct sock *sk, int len, gfp_t priority);
void sock_kfree_s(struct sock *sk, void *mem, int size);
int copy_from_user(void *to, const void *from, unsigned long n);
int sock_sendmsg_nosec(struct socket *sock, struct msghdr *msg);
int __sock_sendmsg(struct socket *sock, struct msghdr *msg);
int memcmp(const void *s1, const void *s2, unsigned long n);
void *memcpy(void *dest, const void *src, unsigned long n);
"""

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(prelude + "\n\n" + body, encoding="utf-8")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"extract sendmsg control bughunt slice failed: {exc}", file=sys.stderr)
        raise SystemExit(2)
