/*
 * Bug-hunting harness for the real Kbuild-derived do_accept slice.
 *
 * The assertions focus on the new socket/new file lifetime and on the peer
 * address error paths that must fput the accepted file before returning ERR_PTR.
 */

#include "socket_contracts_kernel_constants.h"

int nondet_int(void);
unsigned int nondet_uint(void);

static struct module accept_model_module;
static struct proto_ops accept_model_ops;
static struct proto accept_model_proto;
static struct sock accept_listen_sk;
static struct sock accept_new_sk;
static struct socket accept_listen_socket;
static struct socket accept_new_socket;
static struct file accept_listen_file;
static struct file accept_plain_file;
static struct file accept_new_file;

static int model_live_new_sockets;
static int model_live_new_files;
static int model_sock_alloc_calls;
static int model_sock_alloc_successes;
static int model_sock_alloc_file_calls;
static int model_sock_alloc_file_successes;
static int model_sock_release_calls;
static int model_fput_calls;
static int model_module_get_calls;
static int model_security_calls;
static int model_proto_accept_calls;
static int model_getname_calls;
static int model_move_addr_calls;
static int model_initial_arg_flags;
static int model_listen_file_flags;
static int model_expected_accept_flags;
static int model_last_getname_len;

static void accept_model_release_socket(struct socket *sock)
{
	__CPROVER_assert(sock == &accept_new_socket,
			 "accept releases only the newly allocated socket");
	__CPROVER_assert(sock->live, "accept releases a live new socket");
	__CPROVER_assert(!sock->owned_by_file,
			 "accept sock_release is not called on file-owned socket");
	sock->live = 0;
	model_live_new_sockets--;
	model_sock_release_calls++;
}

static void model_reset(void)
{
	accept_model_module.model_id = 1;
	accept_model_ops.owner = &accept_model_module;
	accept_model_ops.accept = 0;
	accept_model_ops.getname = 0;
	accept_model_proto.name = "accept-model";

	accept_listen_sk.sk_prot_creator = &accept_model_proto;
	accept_listen_sk.model_id = 10;
	accept_new_sk.sk_prot_creator = &accept_model_proto;
	accept_new_sk.model_id = 20;

	accept_listen_file.f_flags = 0;
	accept_listen_file.sock = &accept_listen_socket;
	accept_listen_file.model_id = 100;
	accept_listen_file.live = 1;

	accept_plain_file.f_flags = 0;
	accept_plain_file.sock = 0;
	accept_plain_file.model_id = 101;
	accept_plain_file.live = 1;

	accept_new_file.f_flags = 0;
	accept_new_file.sock = 0;
	accept_new_file.model_id = 102;
	accept_new_file.live = 0;

	accept_listen_socket.sk = &accept_listen_sk;
	accept_listen_socket.file = &accept_listen_file;
	accept_listen_socket.type = nondet_int();
	accept_listen_socket.ops = &accept_model_ops;
	accept_listen_socket.model_id = 200;
	accept_listen_socket.live = 1;
	accept_listen_socket.owned_by_file = 1;

	accept_new_socket.sk = &accept_new_sk;
	accept_new_socket.file = 0;
	accept_new_socket.type = 0;
	accept_new_socket.ops = 0;
	accept_new_socket.model_id = 201;
	accept_new_socket.live = 0;
	accept_new_socket.owned_by_file = 0;

	model_live_new_sockets = 0;
	model_live_new_files = 0;
	model_sock_alloc_calls = 0;
	model_sock_alloc_successes = 0;
	model_sock_alloc_file_calls = 0;
	model_sock_alloc_file_successes = 0;
	model_sock_release_calls = 0;
	model_fput_calls = 0;
	model_module_get_calls = 0;
	model_security_calls = 0;
	model_proto_accept_calls = 0;
	model_getname_calls = 0;
	model_move_addr_calls = 0;
	model_initial_arg_flags = 0;
	model_listen_file_flags = 0;
	model_expected_accept_flags = 0;
	model_last_getname_len = -1;
}

static int accept_model_proto_accept(struct socket *sock,
				     struct socket *newsock,
				     struct proto_accept_arg *arg)
{
	unsigned int choice = nondet_uint();

	__CPROVER_assert(sock == &accept_listen_socket,
			 "protocol accept receives the listening socket");
	__CPROVER_assert(newsock == &accept_new_socket,
			 "protocol accept receives the new socket");
	__CPROVER_assert(sock->live && newsock->live,
			 "protocol accept receives live sockets");
	__CPROVER_assert(newsock->owned_by_file && newsock->file == &accept_new_file,
			 "protocol accept receives a file-owned new socket");
	__CPROVER_assert(arg != 0, "protocol accept receives a non-null arg");
	__CPROVER_assert(arg->flags == model_expected_accept_flags,
			 "do_accept ORs listening file flags into arg before protocol accept");
	model_proto_accept_calls++;
	__CPROVER_assume(choice <= 1);
	return choice == 0 ? 0 : -VKERNEL_EPROTONOSUPPORT;
}

static int accept_model_getname(struct socket *sock, struct sockaddr *addr,
				int peer)
{
	unsigned int choice = nondet_uint();
	int len = nondet_int();

	__CPROVER_assert(sock == &accept_new_socket,
			 "getname receives the accepted socket");
	__CPROVER_assert(sock->live && sock->owned_by_file,
			 "getname receives a live file-owned socket");
	__CPROVER_assert(addr != 0, "getname receives kernel address storage");
	__CPROVER_assert(peer == 2, "do_accept asks getname for the peer address");
	model_getname_calls++;
	__CPROVER_assume(choice <= 1);
	if (choice == 1)
		return -VKERNEL_EINVAL;
	__CPROVER_assume(len >= 0 && len <= 128);
	model_last_getname_len = len;
	return len;
}

struct socket *sock_from_file(struct file *file)
{
	__CPROVER_assert(file != 0, "sock_from_file receives a non-null file");
	__CPROVER_assert(file->live, "sock_from_file receives a live file");
	return file->sock;
}

struct socket *sock_alloc(void)
{
	unsigned int choice = nondet_uint();

	model_sock_alloc_calls++;
	__CPROVER_assume(choice <= 1);
	if (choice == 1)
		return 0;
	__CPROVER_assert(!accept_new_socket.live,
			 "sock_alloc does not reuse a live new socket");
	accept_new_socket.live = 1;
	accept_new_socket.owned_by_file = 0;
	accept_new_socket.file = 0;
	accept_new_socket.sk = &accept_new_sk;
	model_live_new_sockets++;
	model_sock_alloc_successes++;
	return &accept_new_socket;
}

void __module_get(struct module *module)
{
	__CPROVER_assert(module == &accept_model_module,
			 "do_accept gets the protocol owner module");
	model_module_get_calls++;
}

struct file *sock_alloc_file(struct socket *sock, int flags, const char *dname)
{
	unsigned int choice = nondet_uint();

	(void)flags;
	model_sock_alloc_file_calls++;
	__CPROVER_assert(sock == &accept_new_socket,
			 "sock_alloc_file receives the new socket");
	__CPROVER_assert(sock->live, "sock_alloc_file receives a live socket");
	__CPROVER_assert(!sock->owned_by_file,
			 "sock_alloc_file receives an unowned socket");
	__CPROVER_assert(dname == accept_model_proto.name,
			 "sock_alloc_file receives the listener protocol name");
	__CPROVER_assume(choice <= 1);
	if (choice == 1) {
		accept_model_release_socket(sock);
		return ERR_PTR(-VKERNEL_ENOMEM);
	}

	__CPROVER_assert(!accept_new_file.live,
			 "sock_alloc_file does not reuse a live file");
	accept_new_file.live = 1;
	accept_new_file.sock = sock;
	accept_new_file.f_flags = flags;
	sock->file = &accept_new_file;
	sock->owned_by_file = 1;
	model_live_new_files++;
	model_sock_alloc_file_successes++;
	return &accept_new_file;
}

int security_socket_accept(struct socket *sock, struct socket *newsock)
{
	unsigned int choice = nondet_uint();

	model_security_calls++;
	__CPROVER_assert(sock == &accept_listen_socket,
			 "security accept receives the listening socket");
	__CPROVER_assert(newsock == &accept_new_socket,
			 "security accept receives the new socket");
	__CPROVER_assert(sock->live && newsock->live,
			 "security accept receives live sockets");
	__CPROVER_assume(choice <= 1);
	return choice == 0 ? 0 : -VKERNEL_EPERM;
}

int move_addr_to_user(struct __kernel_sockaddr_storage *kaddr, int klen,
		      struct sockaddr *uaddr, int *ulen)
{
	unsigned int choice = nondet_uint();

	model_move_addr_calls++;
	__CPROVER_assert(kaddr != 0, "move_addr_to_user receives kernel address");
	__CPROVER_assert(uaddr != 0, "move_addr_to_user receives user address");
	__CPROVER_assert(ulen != 0, "move_addr_to_user receives user length");
	__CPROVER_assert(klen == model_last_getname_len,
			 "move_addr_to_user uses the length returned by getname");
	__CPROVER_assume(choice <= 1);
	if (choice == 1)
		return -VKERNEL_EFAULT;
	*ulen = klen;
	return 0;
}

void fput(struct file *file)
{
	__CPROVER_assert(file == &accept_new_file,
			 "do_accept fputs only the newly allocated file");
	__CPROVER_assert(file->live, "fput receives a live new file");
	__CPROVER_assert(file->sock == &accept_new_socket,
			 "fput receives the file owning the new socket");
	__CPROVER_assert(file->sock->owned_by_file,
			 "fput receives a file-owned socket");
	file->live = 0;
	file->sock->owned_by_file = 0;
	file->sock->file = 0;
	file->sock = 0;
	model_live_new_files--;
	model_fput_calls++;
	accept_model_release_socket(&accept_new_socket);
}

static int accept_result_errno(struct file *result)
{
	if (result == &accept_new_file)
		return 0;
	if (result == ERR_PTR(-VKERNEL_ENOTSOCK))
		return -VKERNEL_ENOTSOCK;
	if (result == ERR_PTR(-VKERNEL_ENFILE))
		return -VKERNEL_ENFILE;
	if (result == ERR_PTR(-VKERNEL_ENOMEM))
		return -VKERNEL_ENOMEM;
	if (result == ERR_PTR(-VKERNEL_EPERM))
		return -VKERNEL_EPERM;
	if (result == ERR_PTR(-VKERNEL_EPROTONOSUPPORT))
		return -VKERNEL_EPROTONOSUPPORT;
	if (result == ERR_PTR(-VKERNEL_ECONNABORTED))
		return -VKERNEL_ECONNABORTED;
	if (result == ERR_PTR(-VKERNEL_EFAULT))
		return -VKERNEL_EFAULT;
	__CPROVER_assert(0, "do_accept returns only modeled file or ERR_PTR");
	return 0;
}

int main(void)
{
	struct proto_accept_arg arg;
	struct sockaddr user_addr;
	int user_addr_len = nondet_int();
	struct file *input_file;
	struct file *result;
	int result_errno;
	int flags = nondet_int();
	unsigned int input_is_socket = nondet_uint();
	unsigned int want_peer_address = nondet_uint();

	__CPROVER_assume(input_is_socket <= 1);
	__CPROVER_assume(want_peer_address <= 1);

	model_reset();
	accept_model_ops.accept = accept_model_proto_accept;
	accept_model_ops.getname = accept_model_getname;
	model_initial_arg_flags = nondet_int();
	model_listen_file_flags = nondet_int();
	model_expected_accept_flags = model_initial_arg_flags | model_listen_file_flags;
	accept_listen_file.f_flags = model_listen_file_flags;
	arg.flags = model_initial_arg_flags;
	arg.err = nondet_int();
	arg.is_empty = nondet_int();
	arg.kern = (_Bool)(nondet_uint() & 1U);

	input_file = input_is_socket ? &accept_listen_file : &accept_plain_file;
	result = do_accept(input_file, &arg,
			   want_peer_address ? &user_addr : 0,
			   want_peer_address ? &user_addr_len : 0,
			   flags);
	result_errno = accept_result_errno(result);

	__CPROVER_assert(result_errno == 0 ||
			 result_errno == -VKERNEL_ENOTSOCK ||
			 result_errno == -VKERNEL_ENFILE ||
			 result_errno == -VKERNEL_ENOMEM ||
			 result_errno == -VKERNEL_EPERM ||
			 result_errno == -VKERNEL_EPROTONOSUPPORT ||
			 result_errno == -VKERNEL_ECONNABORTED ||
			 result_errno == -VKERNEL_EFAULT,
			 "do_accept returns a modeled success or errno");
	__CPROVER_assert(accept_listen_socket.live && accept_listen_file.live,
			 "do_accept keeps the listening file and socket live");
	__CPROVER_assert(model_live_new_sockets == model_live_new_files,
			 "do_accept balances new socket and new file lifetimes on return");
	__CPROVER_assert(model_module_get_calls == model_sock_alloc_successes,
			 "each allocated accept socket takes one module reference");

	if (!input_is_socket) {
		__CPROVER_assert(result_errno == -VKERNEL_ENOTSOCK,
				 "non-socket file returns ENOTSOCK");
		__CPROVER_assert(model_sock_alloc_calls == 0,
				 "non-socket file path allocates no new socket");
	}

	if (result_errno == 0) {
		__CPROVER_assert(result == &accept_new_file,
				 "successful accept returns the newly allocated file");
		__CPROVER_assert(model_sock_alloc_file_successes == 1,
				 "successful accept allocates exactly one file");
		__CPROVER_assert(model_fput_calls == 0,
				 "successful accept does not fput the returned file");
		__CPROVER_assert(model_security_calls == 1 &&
					 model_proto_accept_calls == 1,
				 "successful accept passed security and protocol accept once");
		__CPROVER_assert(accept_new_socket.type == accept_listen_socket.type,
				 "successful accept copies the listening socket type");
		__CPROVER_assert(accept_new_socket.ops == accept_listen_socket.ops,
				 "successful accept copies the listening socket ops");
		if (want_peer_address) {
			__CPROVER_assert(model_getname_calls == 1 &&
						 model_move_addr_calls == 1,
					 "successful peer-address accept exports the peer address once");
		} else {
			__CPROVER_assert(model_getname_calls == 0 &&
						 model_move_addr_calls == 0,
					 "successful accept without peer address skips address export");
		}
	} else {
		__CPROVER_assert(IS_ERR(result), "failed accept returns ERR_PTR");
		__CPROVER_assert(model_live_new_files == 0,
				 "failed accept leaves no live new file");
		__CPROVER_assert(model_live_new_sockets == 0,
				 "failed accept leaves no live new socket");
		if (model_sock_alloc_file_successes)
			__CPROVER_assert(model_fput_calls == 1,
					 "failure after file allocation fputs exactly once");
	}

	return 0;
}
