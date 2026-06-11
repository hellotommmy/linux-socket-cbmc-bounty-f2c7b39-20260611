/*
 * Bug-hunting harness for the real Kbuild-derived __sys_socketpair slice.
 *
 * The assertions intentionally focus on resource accounting. A violation may be
 * a real kernel bug or an overly-weak model; either way it becomes a triage
 * candidate instead of being hidden by assumptions.
 */

#include "socket_contracts_kernel_constants.h"

int nondet_int(void);
unsigned int nondet_uint(void);

#define MODEL_FD1 100
#define MODEL_FD2 101
#define MODEL_FD_ALLOWED_FLAGS \
	((unsigned int)VKERNEL_O_CLOEXEC | (unsigned int)VKERNEL_O_NONBLOCK)

static struct proto_ops socketpair_model_ops;
static struct socket socket_model_sockets[2];
static struct file socket_model_files[2];

static int model_next_socket;
static int model_next_file;
static int model_next_fd;
static int model_reserved_fds;
static int model_installed_fds;
static int model_live_sockets;
static int model_live_files;
static int model_user_writes;
static int model_audit_calls;

static int socketpair_model_proto_socketpair(struct socket *sock1,
					     struct socket *sock2)
{
	unsigned int choice = nondet_uint();

	__CPROVER_assert(sock1 != 0 && sock2 != 0,
			 "proto socketpair receives non-null sockets");
	__CPROVER_assert(sock1->live && sock2->live,
			 "proto socketpair receives live sockets");
	__CPROVER_assume(choice <= 1);
	return choice == 0 ? 0 : -VKERNEL_EPROTONOSUPPORT;
}

static void model_reset(void)
{
	socketpair_model_ops.socketpair = socketpair_model_proto_socketpair;

	socket_model_sockets[0].ops = &socketpair_model_ops;
	socket_model_sockets[0].model_id = 1;
	socket_model_sockets[0].live = 0;
	socket_model_sockets[0].owned_by_file = 0;
	socket_model_files[0].model_id = 1;
	socket_model_files[0].sock = 0;
	socket_model_files[0].live = 0;

	socket_model_sockets[1].ops = &socketpair_model_ops;
	socket_model_sockets[1].model_id = 2;
	socket_model_sockets[1].live = 0;
	socket_model_sockets[1].owned_by_file = 0;
	socket_model_files[1].model_id = 2;
	socket_model_files[1].sock = 0;
	socket_model_files[1].live = 0;

	model_next_socket = 0;
	model_next_file = 0;
	model_next_fd = 0;
	model_reserved_fds = 0;
	model_installed_fds = 0;
	model_live_sockets = 0;
	model_live_files = 0;
	model_user_writes = 0;
	model_audit_calls = 0;
}

static int modeled_error_from_choice(unsigned int choice)
{
	if (choice == 0)
		return -VKERNEL_ENOMEM;
	if (choice == 1)
		return -VKERNEL_EAFNOSUPPORT;
	if (choice == 2)
		return -VKERNEL_EPROTONOSUPPORT;
	return -VKERNEL_EFAULT;
}

int get_unused_fd_flags(unsigned flags)
{
	unsigned int fail = nondet_uint();

	__CPROVER_assert((flags & ~MODEL_FD_ALLOWED_FLAGS) == 0U,
			 "fd reservation receives only supported fd flags");
	__CPROVER_assume(fail <= 1);
	if (fail)
		return -VKERNEL_EMFILE;

	__CPROVER_assert(model_next_fd < 2,
			 "socketpair reserves at most two descriptors");
	model_reserved_fds++;
	return model_next_fd++ == 0 ? MODEL_FD1 : MODEL_FD2;
}

void put_unused_fd(unsigned int fd)
{
	__CPROVER_assert(fd == MODEL_FD1 || fd == MODEL_FD2,
			 "put_unused_fd sees a modeled descriptor");
	__CPROVER_assert(model_reserved_fds > 0,
			 "put_unused_fd does not underflow reservations");
	model_reserved_fds--;
}

int socketpair_model_put_user(int value, int *user_slot)
{
	unsigned int fail = nondet_uint();

	__CPROVER_assert(value == MODEL_FD1 || value == MODEL_FD2,
			 "put_user writes a modeled descriptor");
	__CPROVER_assert(user_slot != 0, "put_user target is non-null");
	__CPROVER_assume(fail <= 1);
	if (fail)
		return -VKERNEL_EFAULT;

	*user_slot = value;
	model_user_writes++;
	return 0;
}

int sock_create(int family, int type, int protocol, struct socket **res)
{
	unsigned int choice = nondet_uint();
	struct socket *sock;

	(void)family;
	(void)protocol;
	__CPROVER_assert(res != 0, "sock_create result pointer is non-null");
	__CPROVER_assert((type & ~VKERNEL_SOCK_TYPE_MASK) == 0,
			 "sock_create receives stripped socket type");
	__CPROVER_assume(choice <= 3);
	if (choice != 0) {
		*res = 0;
		return modeled_error_from_choice(choice - 1);
	}

	__CPROVER_assert(model_next_socket < 2,
			 "socketpair creates at most two sockets");
	sock = &socket_model_sockets[model_next_socket++];
	__CPROVER_assert(!sock->live, "sock_create does not reuse a live socket");
	sock->live = 1;
	sock->owned_by_file = 0;
	sock->ops = &socketpair_model_ops;
	*res = sock;
	model_live_sockets++;
	return 0;
}

void sock_release(struct socket *sock)
{
	__CPROVER_assert(sock != 0, "sock_release receives non-null socket");
	__CPROVER_assert(sock->live, "sock_release receives live socket");
	__CPROVER_assert(!sock->owned_by_file,
			 "sock_release is not called on file-owned socket");
	sock->live = 0;
	model_live_sockets--;
}

int security_socket_socketpair(struct socket *sock1, struct socket *sock2)
{
	unsigned int choice = nondet_uint();

	__CPROVER_assert(sock1 != 0 && sock2 != 0,
			 "security hook receives non-null sockets");
	__CPROVER_assert(sock1->live && sock2->live,
			 "security hook receives live sockets");
	__CPROVER_assume(choice <= 1);
	return choice == 0 ? 0 : -VKERNEL_EPERM;
}

struct file *sock_alloc_file(struct socket *sock, int flags, const char *dname)
{
	unsigned int choice = nondet_uint();
	struct file *file;

	(void)dname;
	__CPROVER_assert(sock != 0, "sock_alloc_file receives non-null socket");
	__CPROVER_assert(sock->live, "sock_alloc_file receives live socket");
	__CPROVER_assert(!sock->owned_by_file,
			 "sock_alloc_file receives socket not already file-owned");
	__CPROVER_assert(flags >= 0, "sock_alloc_file receives non-negative flags");
	__CPROVER_assert(((unsigned int)flags & ~MODEL_FD_ALLOWED_FLAGS) == 0U,
			 "sock_alloc_file receives only fd creation flags");
	__CPROVER_assume(choice <= 1);
	if (choice == 1) {
		sock_release(sock);
		return ERR_PTR(-VKERNEL_ENOMEM);
	}

	__CPROVER_assert(model_next_file < 2,
			 "socketpair allocates at most two files");
	file = &socket_model_files[model_next_file++];
	__CPROVER_assert(!file->live, "sock_alloc_file does not reuse live file");
	file->live = 1;
	file->sock = sock;
	sock->owned_by_file = 1;
	model_live_files++;
	return file;
}

void fput(struct file *file)
{
	__CPROVER_assert(file != 0, "fput receives non-null file");
	__CPROVER_assert(file->live, "fput receives live file");
	__CPROVER_assert(file->sock != 0 && file->sock->live,
			 "fput file owns a live socket");
	file->live = 0;
	file->sock->owned_by_file = 0;
	sock_release(file->sock);
	file->sock = 0;
	model_live_files--;
}

void audit_fd_pair(int fd1, int fd2)
{
	__CPROVER_assert(fd1 == MODEL_FD1 && fd2 == MODEL_FD2,
			 "audit observes the reserved fd pair");
	model_audit_calls++;
}

void fd_install(unsigned int fd, struct file *file)
{
	__CPROVER_assert(fd == MODEL_FD1 || fd == MODEL_FD2,
			 "fd_install sees a modeled descriptor");
	__CPROVER_assert(file != 0 && file->live,
			 "fd_install receives live file");
	__CPROVER_assert(model_reserved_fds > 0,
			 "fd_install consumes a reserved descriptor");
	model_reserved_fds--;
	model_installed_fds++;
}

static int socketpair_valid_result(int result)
{
	return result == 0 || result == -VKERNEL_EINVAL ||
	       result == -VKERNEL_ENOMEM || result == -VKERNEL_EAFNOSUPPORT ||
	       result == -VKERNEL_EPROTONOSUPPORT || result == -VKERNEL_EFAULT ||
	       result == -VKERNEL_EMFILE || result == -VKERNEL_EPERM;
}

int main(void)
{
	int family = nondet_int();
	int type = nondet_int();
	int protocol = nondet_int();
	int user_fds[2] = { -1, -1 };
	int result;

	model_reset();
	result = __sys_socketpair(family, type, protocol, user_fds);

	__CPROVER_assert(socketpair_valid_result(result),
			 "socketpair returns a modeled success or errno");
	__CPROVER_assert(model_reserved_fds == 0,
			 "socketpair leaves no reserved fd leak");

	if (result == 0) {
		__CPROVER_assert(model_installed_fds == 2,
				 "successful socketpair installs exactly two fds");
		__CPROVER_assert(model_live_files == 2,
				 "successful socketpair leaves two file-owned sockets");
		__CPROVER_assert(model_live_sockets == 2,
				 "successful socketpair leaves two live sockets");
		__CPROVER_assert(model_audit_calls == 1,
				 "successful socketpair audits the fd pair once");
		__CPROVER_assert(user_fds[0] == MODEL_FD1 &&
					 user_fds[1] == MODEL_FD2,
				 "successful socketpair reports both installed fds");
	} else {
		__CPROVER_assert(model_installed_fds == 0,
				 "failed socketpair installs no descriptors");
		__CPROVER_assert(model_live_files == 0,
				 "failed socketpair leaves no live files");
		__CPROVER_assert(model_live_sockets == 0,
				 "failed socketpair leaves no live sockets");
		__CPROVER_assert(model_audit_calls == 0,
				 "failed socketpair does not audit fd pair");
	}

	return 0;
}
