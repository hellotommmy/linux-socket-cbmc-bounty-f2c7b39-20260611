// SPDX-License-Identifier: GPL-2.0-or-later
#include "kernel_compat.h"
#include "socket_contracts.h"
#include "socket_model.h"

int nondet_int(void);

int main(void)
{
	int family = nondet_int();
	int type = nondet_int();
	int protocol = nondet_int();
	int result;

	socket_model_reset();

	result = __sys_socket(family, type, protocol);

	if (!socket_has_only_supported_creation_flags(type)) {
		__CPROVER_assert(result == -EINVAL,
				 "invalid socket creation flags return -EINVAL");
		__CPROVER_assert(socket_model_sock_create_calls == 0,
				 "invalid flags do not call sock_create");
		__CPROVER_assert(socket_model_sock_map_fd_calls == 0,
				 "invalid flags do not call sock_map_fd");
	} else {
		__CPROVER_assert(socket_model_sock_create_calls == 1,
				 "valid creation flags call sock_create once");
		__CPROVER_assert(socket_model_sock_create_family == family,
				 "sock_create receives the requested family");
		__CPROVER_assert(
			socket_model_sock_create_type == socket_stripped_type(type),
			"sock_create receives type masked by SOCK_TYPE_MASK");
		__CPROVER_assert(
			socket_model_sock_create_protocol ==
				socket_default_updated_protocol(family, type, protocol),
			"default update_socket_protocol preserves protocol");

		if (socket_model_sock_create_ret < 0) {
			__CPROVER_assert(result == socket_model_sock_create_ret,
					 "sock_create errors propagate exactly");
			__CPROVER_assert(socket_model_sock_map_fd_calls == 0,
					 "sock_create failure skips sock_map_fd");
		} else {
			__CPROVER_assert(socket_model_sock_map_fd_calls == 1,
					 "successful sock_create maps one fd");
			__CPROVER_assert(socket_model_sock_map_fd_sock ==
						 socket_model_created_socket,
					 "sock_map_fd receives the created socket");
			__CPROVER_assert(
				socket_model_sock_map_fd_flags ==
					socket_normalized_fd_flags_from_type(type),
				"sock_map_fd receives normalized fd flags");
			__CPROVER_assert(result == socket_model_sock_map_fd_ret,
					 "sock_map_fd result propagates exactly");
			__CPROVER_assert(socket_modeled_fd_or_error(result),
					 "socket result is a modeled fd or errno");
		}
	}

	return 0;
}

