// SPDX-License-Identifier: GPL-2.0-or-later
#include "kernel_compat.h"
#include "socket_contracts.h"
#include "socket_model.h"

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

static struct socket socket_model_live_socket;
static struct socket socket_model_err_einval;
static struct socket socket_model_err_enomem;
static struct socket socket_model_err_eafnosupport;
static struct socket socket_model_err_eprotonosupport;

void socket_model_reset(void)
{
	socket_model_sock_create_calls = 0;
	socket_model_sock_create_family = 0;
	socket_model_sock_create_type = 0;
	socket_model_sock_create_protocol = 0;
	socket_model_sock_create_ret = 0;
	socket_model_created_socket = NULL;

	socket_model_sock_map_fd_calls = 0;
	socket_model_sock_map_fd_sock = NULL;
	socket_model_sock_map_fd_flags = 0;
	socket_model_sock_map_fd_ret = 0;
}

struct socket *__vk_errno_to_ptr(int error)
{
	__CPROVER_assert(socket_modeled_error(error),
			 "kernel ERR_PTR receives a modeled negative errno");

	if (error == -EINVAL)
		return &socket_model_err_einval;
	if (error == -ENOMEM)
		return &socket_model_err_enomem;
	if (error == -EAFNOSUPPORT)
		return &socket_model_err_eafnosupport;
	if (error == -EPROTONOSUPPORT)
		return &socket_model_err_eprotonosupport;

	__CPROVER_assert(false, "unreachable modeled errno");
	return &socket_model_err_einval;
}

int __vk_ptr_to_errno(const struct socket *ptr)
{
	if (ptr == &socket_model_err_einval)
		return -EINVAL;
	if (ptr == &socket_model_err_enomem)
		return -ENOMEM;
	if (ptr == &socket_model_err_eafnosupport)
		return -EAFNOSUPPORT;
	if (ptr == &socket_model_err_eprotonosupport)
		return -EPROTONOSUPPORT;

	__CPROVER_assert(false, "PTR_ERR is used only with modeled ERR_PTR values");
	return 0;
}

bool __vk_is_err(const struct socket *ptr)
{
	return ptr == &socket_model_err_einval ||
	       ptr == &socket_model_err_enomem ||
	       ptr == &socket_model_err_eafnosupport ||
	       ptr == &socket_model_err_eprotonosupport;
}

static int socket_model_nondet_sock_create_result(void)
{
	unsigned int choice = nondet_uint();

	__CPROVER_assume(choice <= 3);
	if (choice == 0)
		return 0;
	if (choice == 1)
		return -ENOMEM;
	if (choice == 2)
		return -EAFNOSUPPORT;
	return -EPROTONOSUPPORT;
}

int socket_model_sock_create(int family, int type, int protocol,
			     struct socket **res)
{
	int ret;

	socket_model_sock_create_calls++;
	socket_model_sock_create_family = family;
	socket_model_sock_create_type = type;
	socket_model_sock_create_protocol = protocol;

	__CPROVER_assert(res != NULL, "sock_create result pointer is non-null");
	__CPROVER_assert((type & ~SOCK_TYPE_MASK) == 0,
			 "sock_create receives a stripped socket type");

	ret = socket_model_nondet_sock_create_result();
	socket_model_sock_create_ret = ret;

	if (ret == 0) {
		socket_model_live_socket.cbmc_id = 1;
		socket_model_live_socket.cbmc_family = family;
		socket_model_live_socket.cbmc_type = type;
		socket_model_live_socket.cbmc_protocol = protocol;
		*res = &socket_model_live_socket;
		socket_model_created_socket = *res;
	} else {
		*res = NULL;
		socket_model_created_socket = NULL;
	}

	return ret;
}

int socket_model_sock_map_fd(struct socket *sock, int flags)
{
	unsigned int fd_choice = nondet_uint();
	unsigned int err_choice = nondet_uint();
	bool returns_fd = nondet_uint() != 0;

	socket_model_sock_map_fd_calls++;
	socket_model_sock_map_fd_sock = sock;
	socket_model_sock_map_fd_flags = flags;

	__CPROVER_assert(sock != NULL, "sock_map_fd receives a live socket");
	__CPROVER_assert(!IS_ERR(sock), "sock_map_fd never receives ERR_PTR");
	__CPROVER_assert((flags & ~(O_CLOEXEC | O_NONBLOCK)) == 0,
			 "sock_map_fd receives only fd creation flags");

	if (returns_fd) {
		__CPROVER_assume(fd_choice <= 1024);
		socket_model_sock_map_fd_ret = (int)fd_choice;
	} else {
		__CPROVER_assume(err_choice <= 1);
		socket_model_sock_map_fd_ret =
			err_choice == 0 ? -ENOMEM : -EINVAL;
	}

	return socket_model_sock_map_fd_ret;
}

#ifdef SOCKET_MODEL_PROVIDE_KERNEL_SYMBOLS
int sock_create(int family, int type, int protocol, struct socket **res)
{
	return socket_model_sock_create(family, type, protocol, res);
}

int sock_map_fd(struct socket *sock, int flags)
{
	return socket_model_sock_map_fd(sock, flags);
}
#endif
