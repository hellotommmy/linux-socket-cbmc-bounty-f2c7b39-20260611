#!/usr/bin/env python3
import argparse
import sys
from pathlib import Path

from extract_socket_common import find_function

SYMBOLS = ["__sys_socket_create", "update_socket_protocol", "__sys_socket"]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("preprocessed")
    parser.add_argument("output")
    args = parser.parse_args()

    text = Path(args.preprocessed).read_text(encoding="utf-8", errors="replace")
    functions = [find_function(text, symbol) for symbol in SYMBOLS]

    prelude = """/* Generated from Kbuild net/socket.i by extract-socket-proof-slice-from-preprocessed.py. */
#include "socket_contracts_kernel_constants.h"

typedef _Bool bool;
struct socket;

#define SOCK_PACKET VKERNEL_SOCK_PACKET

static int vk_err_einval;
static int vk_err_enomem;
static int vk_err_eafnosupport;
static int vk_err_eprotonosupport;

static void *ERR_PTR(long error)
{
\t__CPROVER_assert(error == -VKERNEL_EINVAL ||
\t\t\t error == -VKERNEL_ENOMEM ||
\t\t\t error == -VKERNEL_EAFNOSUPPORT ||
\t\t\t error == -VKERNEL_EPROTONOSUPPORT,
\t\t\t "ERR_PTR receives a modeled kernel errno");
\tif (error == -VKERNEL_EINVAL)
\t\treturn &vk_err_einval;
\tif (error == -VKERNEL_ENOMEM)
\t\treturn &vk_err_enomem;
\tif (error == -VKERNEL_EAFNOSUPPORT)
\t\treturn &vk_err_eafnosupport;
\treturn &vk_err_eprotonosupport;
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
\t__CPROVER_assert(0, "PTR_ERR is used only with modeled ERR_PTR values");
\treturn 0;
}

static bool IS_ERR(const void *ptr)
{
\treturn ptr == &vk_err_einval ||
\t       ptr == &vk_err_enomem ||
\t       ptr == &vk_err_eafnosupport ||
\t       ptr == &vk_err_eprotonosupport;
}

int sock_create(int family, int type, int protocol, struct socket **res);
int sock_map_fd(struct socket *sock, int flags);
"""

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(prelude + "\n\n" + "\n\n".join(functions) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"extract socket proof slice failed: {exc}", file=sys.stderr)
        raise SystemExit(2)
