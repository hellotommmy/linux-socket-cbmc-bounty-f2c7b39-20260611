/*
 * Appended to the Kbuild-generated net/socket.i translation unit.
 *
 * This file deliberately does not include kernel_compat.h. It relies on the
 * real Linux preprocessed source above it for kernel types such as
 * `struct socket`, and on the generated socket_contracts_kernel_constants.h
 * for numeric flag constants extracted from that same preprocessed source.
 */

#include "socket_contracts_kernel_constants.h"

int nondet_int(void);
unsigned int nondet_uint(void);

int socket_model_sock_create_calls;
int socket_model_sock_create_family;
int socket_model_sock_create_type;
int socket_model_sock_create_protocol;
int socket_model_sock_create_ret;
struct socket *socket_model_created_socket;

int socket_model_sock_map_fd_calls;
struct socket *socket_model_sock_map_fd_sock;
int socket_model_sock_map_fd_flags;
int socket_model_sock_map_fd_ret;

static int socket_model_live_socket_storage;

static int vk_socket_raw_flags(int type)
{
	return type & ~VKERNEL_SOCK_TYPE_MASK;
}

static int vk_socket_stripped_type(int type)
{
	return type & VKERNEL_SOCK_TYPE_MASK;
}

static int vk_socket_has_only_supported_creation_flags(int type)
{
	return (vk_socket_raw_flags(type) &
		~(VKERNEL_SOCK_CLOEXEC | VKERNEL_SOCK_NONBLOCK)) == 0;
}

static int vk_socket_normalized_fd_flags_from_type(int type)
{
	int flags = vk_socket_raw_flags(type);

	if (VKERNEL_SOCK_NONBLOCK != VKERNEL_O_NONBLOCK &&
	    (flags & VKERNEL_SOCK_NONBLOCK))
		flags = (flags & ~VKERNEL_SOCK_NONBLOCK) | VKERNEL_O_NONBLOCK;

	return flags & (VKERNEL_O_CLOEXEC | VKERNEL_O_NONBLOCK);
}

static int vk_socket_modeled_error(int result)
{
	return result == -VKERNEL_EINVAL || result == -VKERNEL_ENOMEM ||
	       result == -VKERNEL_EAFNOSUPPORT ||
	       result == -VKERNEL_EPROTONOSUPPORT;
}

static int vk_socket_modeled_fd_or_error(int result)
{
	return result >= 0 || vk_socket_modeled_error(result);
}

void socket_model_reset(void)
{
	socket_model_sock_create_calls = 0;
	socket_model_sock_create_family = 0;
	socket_model_sock_create_type = 0;
	socket_model_sock_create_protocol = 0;
	socket_model_sock_create_ret = 0;
	socket_model_created_socket = 0;

	socket_model_sock_map_fd_calls = 0;
	socket_model_sock_map_fd_sock = 0;
	socket_model_sock_map_fd_flags = 0;
	socket_model_sock_map_fd_ret = 0;
}

static int socket_model_nondet_sock_create_result(void)
{
	unsigned int choice = nondet_uint();

	__CPROVER_assume(choice <= 3);
	if (choice == 0)
		return 0;
	if (choice == 1)
		return -VKERNEL_ENOMEM;
	if (choice == 2)
		return -VKERNEL_EAFNOSUPPORT;
	return -VKERNEL_EPROTONOSUPPORT;
}

int socket_model_sock_create(int family, int type, int protocol,
			     struct socket **res)
{
	int ret;

	socket_model_sock_create_calls++;
	socket_model_sock_create_family = family;
	socket_model_sock_create_type = type;
	socket_model_sock_create_protocol = protocol;

	__CPROVER_assert(res != 0, "sock_create result pointer is non-null");
	__CPROVER_assert((type & ~VKERNEL_SOCK_TYPE_MASK) == 0,
			 "sock_create receives a stripped socket type");

	ret = socket_model_nondet_sock_create_result();
	socket_model_sock_create_ret = ret;

	if (ret == 0) {
		*res = (struct socket *)&socket_model_live_socket_storage;
		socket_model_created_socket = *res;
	} else {
		*res = 0;
		socket_model_created_socket = 0;
	}

	return ret;
}

int socket_model_sock_map_fd(struct socket *sock, int flags)
{
	unsigned int fd_choice = nondet_uint();
	unsigned int err_choice = nondet_uint();
	int returns_fd = nondet_uint() != 0;

	socket_model_sock_map_fd_calls++;
	socket_model_sock_map_fd_sock = sock;
	socket_model_sock_map_fd_flags = flags;

	__CPROVER_assert(sock != 0, "sock_map_fd receives a live socket");
	__CPROVER_assert((flags & ~(VKERNEL_O_CLOEXEC | VKERNEL_O_NONBLOCK)) == 0,
			 "sock_map_fd receives only fd creation flags");

	if (returns_fd) {
		__CPROVER_assume(fd_choice <= 1024);
		socket_model_sock_map_fd_ret = (int)fd_choice;
	} else {
		__CPROVER_assume(err_choice <= 1);
		socket_model_sock_map_fd_ret =
			err_choice == 0 ? -VKERNEL_ENOMEM : -VKERNEL_EINVAL;
	}

	return socket_model_sock_map_fd_ret;
}

int main(void)
{
	int family = nondet_int();
	int type = nondet_int();
	int protocol = nondet_int();
	int result;

	socket_model_reset();

	result = __sys_socket(family, type, protocol);

	if (!vk_socket_has_only_supported_creation_flags(type)) {
		__CPROVER_assert(result == -VKERNEL_EINVAL,
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
			socket_model_sock_create_type == vk_socket_stripped_type(type),
			"sock_create receives type masked by SOCK_TYPE_MASK");
		__CPROVER_assert(socket_model_sock_create_protocol == protocol,
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
					vk_socket_normalized_fd_flags_from_type(type),
				"sock_map_fd receives normalized fd flags");
			__CPROVER_assert(result == socket_model_sock_map_fd_ret,
					 "sock_map_fd result propagates exactly");
			__CPROVER_assert(vk_socket_modeled_fd_or_error(result),
					 "socket result is a modeled fd or errno");
		}
	}

	return 0;
}
