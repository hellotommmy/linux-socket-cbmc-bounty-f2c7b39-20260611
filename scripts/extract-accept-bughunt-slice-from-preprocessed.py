#!/usr/bin/env python3
import argparse
import sys
from pathlib import Path

from extract_socket_common import find_function


def rewrite_accept_body(body: str) -> str:
    rewritten = []
    read_once_rewrite = 0

    for line in body.splitlines():
        if "ops = ({ do {" in line and "__compiletime_assert_" in line and "sock->ops" in line:
            rewritten.append("\tops = sock->ops;")
            read_once_rewrite += 1
            continue
        rewritten.append(line)

    if read_once_rewrite != 1:
        raise ValueError(
            "unexpected accept rewrite counts: "
            f"read_once_rewrite={read_once_rewrite}"
        )
    return "\n".join(rewritten) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("preprocessed")
    parser.add_argument("output")
    args = parser.parse_args()

    text = Path(args.preprocessed).read_text(encoding="utf-8", errors="replace")
    body = rewrite_accept_body(find_function(text, "do_accept"))

    prelude = """/* Generated from Kbuild net/socket.i by extract-accept-bughunt-slice-from-preprocessed.py. */
#include "socket_contracts_kernel_constants.h"

typedef _Bool bool;

#ifndef true
#define true ((_Bool)1)
#endif
#ifndef false
#define false ((_Bool)0)
#endif

struct module {
\tint model_id;
};

struct sockaddr {
\tunsigned char bytes[16];
};

struct __kernel_sockaddr_storage {
\tunsigned char bytes[128];
};

struct proto {
\tconst char *name;
};

struct sock {
\tstruct proto *sk_prot_creator;
\tint model_id;
};

struct proto_accept_arg {
\tint flags;
\tint err;
\tint is_empty;
\tbool kern;
};

struct socket;

struct file {
\tint f_flags;
\tstruct socket *sock;
\tint model_id;
\tbool live;
};

struct proto_ops {
\tstruct module *owner;
\tint (*accept)(struct socket *sock, struct socket *newsock,
\t\t\t      struct proto_accept_arg *arg);
\tint (*getname)(struct socket *sock, struct sockaddr *addr, int peer);
};

struct socket {
\tstruct sock *sk;
\tstruct file *file;
\tint type;
\tconst struct proto_ops *ops;
\tint model_id;
\tbool live;
\tbool owned_by_file;
};

static int vk_err_enotsock;
static int vk_err_enfile;
static int vk_err_enomem;
static int vk_err_eperm;
static int vk_err_eprotonosupport;
static int vk_err_econnaborted;
static int vk_err_efault;

static void *ERR_PTR(long error)
{
\t__CPROVER_assert(error == -VKERNEL_ENOTSOCK ||
\t\t\t error == -VKERNEL_ENFILE ||
\t\t\t error == -VKERNEL_ENOMEM ||
\t\t\t error == -VKERNEL_EPERM ||
\t\t\t error == -VKERNEL_EPROTONOSUPPORT ||
\t\t\t error == -VKERNEL_ECONNABORTED ||
\t\t\t error == -VKERNEL_EFAULT,
\t\t\t "ERR_PTR receives a modeled accept errno");
\tif (error == -VKERNEL_ENOTSOCK)
\t\treturn &vk_err_enotsock;
\tif (error == -VKERNEL_ENFILE)
\t\treturn &vk_err_enfile;
\tif (error == -VKERNEL_ENOMEM)
\t\treturn &vk_err_enomem;
\tif (error == -VKERNEL_EPERM)
\t\treturn &vk_err_eperm;
\tif (error == -VKERNEL_EPROTONOSUPPORT)
\t\treturn &vk_err_eprotonosupport;
\tif (error == -VKERNEL_ECONNABORTED)
\t\treturn &vk_err_econnaborted;
\treturn &vk_err_efault;
}

static bool IS_ERR(const void *ptr)
{
\treturn ptr == &vk_err_enotsock ||
\t       ptr == &vk_err_enfile ||
\t       ptr == &vk_err_enomem ||
\t       ptr == &vk_err_eperm ||
\t       ptr == &vk_err_eprotonosupport ||
\t       ptr == &vk_err_econnaborted ||
\t       ptr == &vk_err_efault;
}

struct socket *sock_from_file(struct file *file);
struct socket *sock_alloc(void);
void __module_get(struct module *module);
struct file *sock_alloc_file(struct socket *sock, int flags, const char *dname);
int security_socket_accept(struct socket *sock, struct socket *newsock);
int move_addr_to_user(struct __kernel_sockaddr_storage *kaddr, int klen,
\t\t\t      struct sockaddr *uaddr, int *ulen);
void fput(struct file *file);
"""

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(prelude + "\n\n" + body, encoding="utf-8")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"extract accept bughunt slice failed: {exc}", file=sys.stderr)
        raise SystemExit(2)
