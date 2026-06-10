/*
 * Bug-hunting harness for the real Kbuild-derived do_sock_setsockopt slice.
 *
 * This target focuses on dispatch ordering, early exits, and the BPF-disabled
 * cleanup boundary produced by the current Kbuild configuration.
 */

#include "socket_contracts_kernel_constants.h"

int nondet_int(void);
unsigned int nondet_uint(void);

static struct sock setsockopt_model_sk;
static struct proto_ops setsockopt_model_ops;
static struct socket setsockopt_model_socket;
static char setsockopt_user_value[8];
static char setsockopt_kernel_value[8];

static int model_security_calls;
static int model_custom_sol_checks;
static int model_sock_setsockopt_calls;
static int model_proto_setsockopt_calls;
static int model_kfree_calls;
static int model_security_result;
static int model_dispatch_result;
static int model_custom_sol_socket;
static int model_last_level;
static int model_last_optname;
static int model_last_optlen;

static bool same_sockptr(sockptr_t a, sockptr_t b)
{
	if (a.is_kernel != b.is_kernel)
		return false;
	if (a.is_kernel)
		return a.kernel == b.kernel;
	return a.user == b.user;
}

static sockptr_t expected_optval(bool kernel)
{
	sockptr_t expected;

	if (kernel) {
		expected.kernel = setsockopt_kernel_value;
		expected.is_kernel = true;
	} else {
		expected.user = setsockopt_user_value;
		expected.is_kernel = false;
	}
	return expected;
}

static void model_reset(void)
{
	setsockopt_model_sk.model_id = 1;
	setsockopt_model_ops.setsockopt = 0;
	setsockopt_model_socket.sk = &setsockopt_model_sk;
	setsockopt_model_socket.ops = &setsockopt_model_ops;
	setsockopt_model_socket.flags = 0;
	setsockopt_model_socket.model_id = 10;

	model_security_calls = 0;
	model_custom_sol_checks = 0;
	model_sock_setsockopt_calls = 0;
	model_proto_setsockopt_calls = 0;
	model_kfree_calls = 0;
	model_security_result = 0;
	model_dispatch_result = 0;
	model_custom_sol_socket = 0;
	model_last_level = 0;
	model_last_optname = 0;
	model_last_optlen = 0;
}

int security_socket_setsockopt(struct socket *sock, int level, int optname)
{
	unsigned int choice = nondet_uint();

	__CPROVER_assert(sock == &setsockopt_model_socket,
			 "security setsockopt receives the modeled socket");
	model_security_calls++;
	model_last_level = level;
	model_last_optname = optname;
	__CPROVER_assume(choice <= 1);
	model_security_result = choice == 0 ? 0 : -VKERNEL_EPERM;
	return model_security_result;
}

bool sock_use_custom_sol_socket(const struct socket *sock)
{
	__CPROVER_assert(sock == &setsockopt_model_socket,
			 "custom SOL_SOCKET check receives the modeled socket");
	model_custom_sol_checks++;
	return (_Bool)model_custom_sol_socket;
}

int sock_setsockopt(struct socket *sock, int level, int optname,
		    sockptr_t optval, int optlen)
{
	unsigned int choice = nondet_uint();

	__CPROVER_assert(sock == &setsockopt_model_socket,
			 "SOL_SOCKET setsockopt receives the modeled socket");
	__CPROVER_assert(sock->sk == &setsockopt_model_sk,
			 "SOL_SOCKET setsockopt sees the modeled sock");
	__CPROVER_assert(level == VKERNEL_SOL_SOCKET,
			 "sock_setsockopt handles only SOL_SOCKET level");
	__CPROVER_assert(!model_custom_sol_socket,
			 "default SOL_SOCKET path is used only without custom handler");
	__CPROVER_assert(same_sockptr(optval, expected_optval(optval.is_kernel)),
			 "sock_setsockopt receives the original optval sockptr");
	__CPROVER_assert(optlen >= 0,
			 "sock_setsockopt is called only with nonnegative optlen");
	model_sock_setsockopt_calls++;
	model_last_level = level;
	model_last_optname = optname;
	model_last_optlen = optlen;
	__CPROVER_assume(choice <= 1);
	model_dispatch_result = choice == 0 ? 0 : -VKERNEL_EINVAL;
	return model_dispatch_result;
}

static int setsockopt_model_proto_setsockopt(struct socket *sock, int level,
					     int optname, sockptr_t optval,
					     int optlen)
{
	unsigned int choice = nondet_uint();

	__CPROVER_assert(sock == &setsockopt_model_socket,
			 "protocol setsockopt receives the modeled socket");
	__CPROVER_assert(level != VKERNEL_SOL_SOCKET || model_custom_sol_socket,
			 "protocol setsockopt handles non-SOL or custom SOL_SOCKET");
	__CPROVER_assert(same_sockptr(optval, expected_optval(optval.is_kernel)),
			 "protocol setsockopt receives the original optval sockptr");
	__CPROVER_assert(optlen >= 0,
			 "protocol setsockopt is called only with nonnegative optlen");
	model_proto_setsockopt_calls++;
	model_last_level = level;
	model_last_optname = optname;
	model_last_optlen = optlen;
	__CPROVER_assume(choice <= 1);
	model_dispatch_result = choice == 0 ? 0 : -VKERNEL_EINVAL;
	return model_dispatch_result;
}

void kfree(const void *ptr)
{
	__CPROVER_assert(ptr == 0,
			 "BPF-disabled setsockopt cleanup frees only NULL kernel_optval");
	model_kfree_calls++;
}

int main(void)
{
	sockptr_t optval;
	int level = nondet_int();
	int optname = nondet_int();
	int optlen = nondet_int();
	int result;
	unsigned int compat_choice = nondet_uint();
	unsigned int proto_present = nondet_uint();
	unsigned int optval_kernel = nondet_uint();
	unsigned int custom_sol_choice = nondet_uint();

	__CPROVER_assume(compat_choice <= 1);
	__CPROVER_assume(proto_present <= 1);
	__CPROVER_assume(optval_kernel <= 1);
	__CPROVER_assume(custom_sol_choice <= 1);

	model_reset();
	model_custom_sol_socket = (int)custom_sol_choice;
	if (proto_present)
		setsockopt_model_ops.setsockopt = setsockopt_model_proto_setsockopt;

	optval.user = setsockopt_user_value;
	optval.is_kernel = false;
	if (optval_kernel) {
		optval.kernel = setsockopt_kernel_value;
		optval.is_kernel = true;
	}

	result = do_sock_setsockopt(&setsockopt_model_socket,
				    (_Bool)compat_choice, level, optname,
				    optval, optlen);

	__CPROVER_assert(result == 0 ||
			 result == -VKERNEL_EPERM ||
			 result == -VKERNEL_EINVAL ||
			 result == -VKERNEL_EOPNOTSUPP,
			 "setsockopt returns a modeled success or errno");

	if (optlen < 0) {
		__CPROVER_assert(result == -VKERNEL_EINVAL,
				 "negative optlen returns EINVAL");
		__CPROVER_assert(model_security_calls == 0 &&
					 model_sock_setsockopt_calls == 0 &&
					 model_proto_setsockopt_calls == 0,
				 "negative optlen skips security and dispatch");
		__CPROVER_assert(model_kfree_calls == 0,
				 "negative optlen skips BPF cleanup");
	}

	if (optlen >= 0) {
		__CPROVER_assert(model_security_calls == 1,
				 "nonnegative optlen reaches security once");
	}

	if (optlen >= 0 && model_security_result) {
		__CPROVER_assert(result == model_security_result,
				 "security setsockopt error returns immediately");
		__CPROVER_assert(model_sock_setsockopt_calls == 0 &&
					 model_proto_setsockopt_calls == 0,
				 "security failure skips setsockopt dispatch");
		__CPROVER_assert(model_kfree_calls == 0,
				 "security failure skips BPF cleanup");
	}

	if (optlen >= 0 && !model_security_result) {
		__CPROVER_assert(model_kfree_calls == 1,
				 "post-security setsockopt executes the cleanup edge once");
	}

	if (optlen >= 0 && !model_security_result &&
	    level == VKERNEL_SOL_SOCKET && !model_custom_sol_socket) {
		__CPROVER_assert(model_custom_sol_checks == 1,
				 "default SOL_SOCKET path checks custom handler once");
		__CPROVER_assert(model_sock_setsockopt_calls == 1 &&
					 model_proto_setsockopt_calls == 0,
				 "default SOL_SOCKET dispatches to sock_setsockopt only");
		__CPROVER_assert(result == model_dispatch_result,
				 "default SOL_SOCKET dispatch result propagates");
	}

	if (optlen >= 0 && !model_security_result &&
	    level == VKERNEL_SOL_SOCKET && model_custom_sol_socket && proto_present) {
		__CPROVER_assert(model_proto_setsockopt_calls == 1,
				 "custom SOL_SOCKET dispatches to protocol setsockopt");
		__CPROVER_assert(model_sock_setsockopt_calls == 0,
				 "custom SOL_SOCKET skips default sock_setsockopt");
		__CPROVER_assert(result == model_dispatch_result,
				 "custom SOL_SOCKET protocol result propagates");
	}

	if (optlen >= 0 && !model_security_result &&
	    level != VKERNEL_SOL_SOCKET && proto_present) {
		__CPROVER_assert(model_custom_sol_checks == 0,
				 "non-SOL_SOCKET path skips custom SOL_SOCKET check");
		__CPROVER_assert(model_proto_setsockopt_calls == 1,
				 "non-SOL_SOCKET dispatches to protocol setsockopt");
		__CPROVER_assert(result == model_dispatch_result,
				 "non-SOL_SOCKET protocol result propagates");
	}

	if (optlen >= 0 && !model_security_result && !proto_present &&
	    (level != VKERNEL_SOL_SOCKET || model_custom_sol_socket)) {
		__CPROVER_assert(result == -VKERNEL_EOPNOTSUPP,
				 "missing protocol setsockopt returns EOPNOTSUPP");
		__CPROVER_assert(model_sock_setsockopt_calls == 0 &&
					 model_proto_setsockopt_calls == 0,
				 "missing protocol setsockopt skips callbacks");
	}

	return 0;
}
