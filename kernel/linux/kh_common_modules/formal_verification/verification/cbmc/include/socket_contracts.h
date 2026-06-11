// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef VKERNEL_CBMC_SOCKET_CONTRACTS_H
#define VKERNEL_CBMC_SOCKET_CONTRACTS_H

#include "kernel_compat.h"

static inline int socket_raw_flags(int type)
{
	return type & ~SOCK_TYPE_MASK;
}

static inline int socket_stripped_type(int type)
{
	return type & SOCK_TYPE_MASK;
}

static inline bool socket_has_only_supported_creation_flags(int type)
{
	return (socket_raw_flags(type) & ~(SOCK_CLOEXEC | SOCK_NONBLOCK)) == 0;
}

static inline int socket_normalized_fd_flags_from_type(int type)
{
	int flags = socket_raw_flags(type);

	if (SOCK_NONBLOCK != O_NONBLOCK && (flags & SOCK_NONBLOCK))
		flags = (flags & ~SOCK_NONBLOCK) | O_NONBLOCK;

	return flags & (O_CLOEXEC | O_NONBLOCK);
}

static inline bool socket_modeled_error(int result)
{
	return result == -EINVAL || result == -ENOMEM ||
	       result == -EAFNOSUPPORT || result == -EPROTONOSUPPORT;
}

static inline bool socket_modeled_fd_or_error(int result)
{
	return result >= 0 || socket_modeled_error(result);
}

static inline int socket_default_updated_protocol(int family, int type,
						  int protocol)
{
	(void)family;
	(void)type;
	return protocol;
}

#endif

