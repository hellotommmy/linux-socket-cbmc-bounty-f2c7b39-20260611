// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef VKERNEL_CBMC_KERNEL_COMPAT_H
#define VKERNEL_CBMC_KERNEL_COMPAT_H

#include <stdbool.h>
#include <stddef.h>

#define EINVAL 22
#define ENOMEM 12
#define EAFNOSUPPORT 97
#define EPROTONOSUPPORT 93

#define SOCK_STREAM 1
#define SOCK_DGRAM 2
#define SOCK_RAW 3
#define SOCK_RDM 4
#define SOCK_SEQPACKET 5
#define SOCK_DCCP 6
#define SOCK_PACKET 10
#define SOCK_MAX SOCK_PACKET
#define SOCK_TYPE_MASK 0xf

#ifndef O_CLOEXEC
#define O_CLOEXEC 02000000
#endif

#ifndef SOCK_CLOEXEC
#define SOCK_CLOEXEC O_CLOEXEC
#endif

#ifndef O_NONBLOCK
#define O_NONBLOCK 00004000
#endif

#ifndef SOCK_NONBLOCK
#define SOCK_NONBLOCK O_NONBLOCK
#endif

#define BUILD_BUG_ON(condition) ((void)sizeof(char[1 - 2 * !!(condition)]))

#ifndef __weak
#define __weak
#endif

#ifndef noinline
#define noinline
#endif

#define __bpf_hook_start()
#define __bpf_hook_end()

struct socket {
	int cbmc_id;
	int cbmc_family;
	int cbmc_type;
	int cbmc_protocol;
};

struct socket *__vk_errno_to_ptr(int error);
int __vk_ptr_to_errno(const struct socket *ptr);
bool __vk_is_err(const struct socket *ptr);

#define ERR_PTR(error) __vk_errno_to_ptr(error)
#define PTR_ERR(ptr) __vk_ptr_to_errno(ptr)
#define IS_ERR(ptr) __vk_is_err(ptr)

int sock_create(int family, int type, int protocol, struct socket **res);
int sock_map_fd(struct socket *sock, int flags);
int update_socket_protocol(int family, int type, int protocol);
int __sys_socket(int family, int type, int protocol);

#endif

