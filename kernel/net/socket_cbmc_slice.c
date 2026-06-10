// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Source-level CBMC slice from Linux net/socket.c.
 *
 * Upstream reference:
 *   https://github.com/torvalds/linux/blob/master/net/socket.c
 *
 * The proof keeps the production control/data flow for __sys_socket_create()
 * and __sys_socket(), while kernel services are supplied by CBMC models.
 */

#include "kernel_compat.h"

// VKERNEL_VERIFIED_BEGIN net/socket.c:__sys_socket_create,__sys_socket
static struct socket *__sys_socket_create(int family, int type, int protocol)
{
	struct socket *sock;
	int retval;

	/* Check the SOCK_* constants for consistency. */
	BUILD_BUG_ON(SOCK_CLOEXEC != O_CLOEXEC);
	BUILD_BUG_ON((SOCK_MAX | SOCK_TYPE_MASK) != SOCK_TYPE_MASK);
	BUILD_BUG_ON(SOCK_CLOEXEC & SOCK_TYPE_MASK);
	BUILD_BUG_ON(SOCK_NONBLOCK & SOCK_TYPE_MASK);

	if ((type & ~SOCK_TYPE_MASK) & ~(SOCK_CLOEXEC | SOCK_NONBLOCK))
		return ERR_PTR(-EINVAL);
	type &= SOCK_TYPE_MASK;

	retval = sock_create(family, type, protocol, &sock);
	if (retval < 0)
		return ERR_PTR(retval);

	return sock;
}

__bpf_hook_start();
__weak noinline int update_socket_protocol(int family, int type, int protocol)
{
	return protocol;
}
__bpf_hook_end();

int __sys_socket(int family, int type, int protocol)
{
	struct socket *sock;
	int flags;

	sock = __sys_socket_create(family, type,
				   update_socket_protocol(family, type, protocol));
	if (IS_ERR(sock))
		return PTR_ERR(sock);

	flags = type & ~SOCK_TYPE_MASK;
	if (SOCK_NONBLOCK != O_NONBLOCK && (flags & SOCK_NONBLOCK))
		flags = (flags & ~SOCK_NONBLOCK) | O_NONBLOCK;

	return sock_map_fd(sock, flags & (O_CLOEXEC | O_NONBLOCK));
}
// VKERNEL_VERIFIED_END

