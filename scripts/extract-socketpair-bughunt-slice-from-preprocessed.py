#!/usr/bin/env python3
import argparse
import sys
from pathlib import Path

from extract_socket_common import find_function


def rewrite_socketpair_body(body: str) -> str:
    rewritten = []
    put_user_0 = 0
    put_user_1 = 0
    proto_ops = 0

    for line in body.splitlines():
        if 'asm volatile("call __" "put_user"' in line and "&usockvec[0]" in line:
            rewritten.append("\terr = socketpair_model_put_user(fd1, &usockvec[0]);")
            put_user_0 += 1
        elif 'asm volatile("call __" "put_user"' in line and "&usockvec[1]" in line:
            rewritten.append("\terr = socketpair_model_put_user(fd2, &usockvec[1]);")
            put_user_1 += 1
        elif "->socketpair(sock1, sock2);" in line:
            rewritten.append("\terr = sock1->ops->socketpair(sock1, sock2);")
            proto_ops += 1
        else:
            rewritten.append(line)

    if put_user_0 != 1 or put_user_1 != 1 or proto_ops != 1:
        raise ValueError(
            "unexpected socketpair rewrite counts: "
            f"put_user_0={put_user_0}, put_user_1={put_user_1}, proto_ops={proto_ops}"
        )
    return "\n".join(rewritten) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("preprocessed")
    parser.add_argument("output")
    args = parser.parse_args()

    text = Path(args.preprocessed).read_text(encoding="utf-8", errors="replace")
    body = rewrite_socketpair_body(find_function(text, "__sys_socketpair"))

    prelude = """/* Generated from Kbuild net/socket.i by extract-socketpair-bughunt-slice-from-preprocessed.py. */
#include "socket_contracts_kernel_constants.h"

typedef _Bool bool;

struct socket;
struct file {
\tint model_id;
\tstruct socket *sock;
\tbool live;
};

struct proto_ops {
\tint (*socketpair)(struct socket *sock1, struct socket *sock2);
};

struct socket {
\tconst struct proto_ops *ops;
\tint model_id;
\tbool live;
\tbool owned_by_file;
};

#define SOCK_PACKET VKERNEL_SOCK_PACKET

static int vk_err_einval;
static int vk_err_enomem;
static int vk_err_eafnosupport;
static int vk_err_eprotonosupport;
static int vk_err_efault;

static void *ERR_PTR(long error)
{
\t__CPROVER_assert(error == -VKERNEL_EINVAL ||
\t\t\t error == -VKERNEL_ENOMEM ||
\t\t\t error == -VKERNEL_EAFNOSUPPORT ||
\t\t\t error == -VKERNEL_EPROTONOSUPPORT ||
\t\t\t error == -VKERNEL_EFAULT,
\t\t\t "ERR_PTR receives a modeled kernel errno");
\tif (error == -VKERNEL_EINVAL)
\t\treturn &vk_err_einval;
\tif (error == -VKERNEL_ENOMEM)
\t\treturn &vk_err_enomem;
\tif (error == -VKERNEL_EAFNOSUPPORT)
\t\treturn &vk_err_eafnosupport;
\tif (error == -VKERNEL_EPROTONOSUPPORT)
\t\treturn &vk_err_eprotonosupport;
\treturn &vk_err_efault;
}

static long PTR_ERR(const void *ptr)
{
\tif (ptr == &vk_err_einval)
\t\treturn -VKERNEL_EINVAL;
\tif (ptr == &vk_err_enomem)
\t\treturn -VKERNEL_ENOMEM;
\tif (ptr == &vk_err_eafnosupport)
\t\treturn -VKERNEL_EAFNOSUPPORT;
\tif (ptr == &vk_err_eprotonosupport)
\t\treturn -VKERNEL_EPROTONOSUPPORT;
\tif (ptr == &vk_err_efault)
\t\treturn -VKERNEL_EFAULT;
\t__CPROVER_assert(0, "PTR_ERR is used only with modeled ERR_PTR values");
\treturn 0;
}

static bool IS_ERR(const void *ptr)
{
\treturn ptr == &vk_err_einval ||
\t       ptr == &vk_err_enomem ||
\t       ptr == &vk_err_eafnosupport ||
\t       ptr == &vk_err_eprotonosupport ||
\t       ptr == &vk_err_efault;
}

int get_unused_fd_flags(unsigned flags);
void put_unused_fd(unsigned int fd);
int socketpair_model_put_user(int value, int *user_slot);
int sock_create(int family, int type, int protocol, struct socket **res);
void sock_release(struct socket *sock);
int security_socket_socketpair(struct socket *sock1, struct socket *sock2);
struct file *sock_alloc_file(struct socket *sock, int flags, const char *dname);
void fput(struct file *file);
void audit_fd_pair(int fd1, int fd2);
void fd_install(unsigned int fd, struct file *file);
"""

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(prelude + "\n\n" + body, encoding="utf-8")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"extract socketpair bughunt slice failed: {exc}", file=sys.stderr)
        raise SystemExit(2)

