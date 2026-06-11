/*
 * Bug-hunting harness for the real Kbuild-derived do_sock_getsockopt slice.
 *
 * This target is bound to the current Kbuild configuration, where the cgroup
 * BPF getsockopt macro preprocesses to the dispatch result itself.
 */

#include "socket_contracts_kernel_constants.h"

int nondet_int(void);
unsigned int nondet_uint(void);

static struct sock getsockopt_model_sk;
static struct proto_ops getsockopt_model_ops;
static struct socket getsockopt_model_socket;
static char getsockopt_user_value[8];
static char getsockopt_kernel_value[8];
static int getsockopt_user_len;
static int getsockopt_kernel_len;

static int model_security_calls;
static int model_copy_calls;
static int model_copy_failed;
static int model_sk_getsockopt_calls;
static int model_proto_getsockopt_calls;
static int model_security_result;
static int model_dispatch_result;
static int model_last_level;
static int model_last_optname;

static int getsockopt_model_proto_getsockopt(struct socket *sock, int level,
					     int optname, char *optval,
					     int *optlen)
{
	unsigned int choice = nondet_uint();

	__CPROVER_assert(sock == &getsockopt_model_socket,
			 "legacy getsockopt receives the modeled socket");
	__CPROVER_assert(level != VKERNEL_SOL_SOCKET,
			 "legacy getsockopt is not used for SOL_SOCKET");
	__CPROVER_assert(optval == getsockopt_user_value,
			 "legacy getsockopt receives user optval pointer");
	__CPROVER_assert(optlen == &getsockopt_user_len,
			 "legacy getsockopt receives user optlen pointer");
	model_proto_getsockopt_calls++;
	model_last_level = level;
	model_last_optname = optname;
	__CPROVER_assume(choice <= 1);
	model_dispatch_result = choice == 0 ? 0 : -VKERNEL_EINVAL;
	return model_dispatch_result;
}

static void model_reset(void)
{
	getsockopt_model_sk.model_id = 1;
	getsockopt_model_ops.getsockopt = 0;
	getsockopt_model_socket.sk = &getsockopt_model_sk;
	getsockopt_model_socket.ops = &getsockopt_model_ops;
	getsockopt_model_socket.model_id = 10;
	getsockopt_user_len = nondet_int();
	getsockopt_kernel_len = nondet_int();

	model_security_calls = 0;
	model_copy_calls = 0;
	model_copy_failed = 0;
	model_sk_getsockopt_calls = 0;
	model_proto_getsockopt_calls = 0;
	model_security_result = 0;
	model_dispatch_result = 0;
	model_last_level = 0;
	model_last_optname = 0;
}

static bool same_sockptr(sockptr_t a, sockptr_t b)
{
	if (a.is_kernel != b.is_kernel)
		return false;
	if (a.is_kernel)
		return a.kernel == b.kernel;
	return a.user == b.user;
}

int security_socket_getsockopt(struct socket *sock, int level, int optname)
{
	unsigned int choice = nondet_uint();

	__CPROVER_assert(sock == &getsockopt_model_socket,
			 "security getsockopt receives the modeled socket");
	model_security_calls++;
	model_last_level = level;
	model_last_optname = optname;
	__CPROVER_assume(choice <= 1);
	model_security_result = choice == 0 ? 0 : -VKERNEL_EPERM;
	return model_security_result;
}

int copy_from_sockptr(void *dst, sockptr_t src, size_t size)
{
	unsigned int choice = nondet_uint();

	__CPROVER_assert(dst != 0, "copy_from_sockptr receives destination storage");
	__CPROVER_assert(size == sizeof(int),
			 "getsockopt reads exactly one int optlen");
	model_copy_calls++;
	if (src.is_kernel) {
		__CPROVER_assert(src.kernel == &getsockopt_kernel_len,
				 "kernel optlen read uses modeled kernel storage");
		*(int *)dst = getsockopt_kernel_len;
		return 0;
	}

	__CPROVER_assert(src.user == &getsockopt_user_len,
			 "user optlen read uses modeled user storage");
	__CPROVER_assume(choice <= 1);
	if (choice == 1) {
		model_copy_failed++;
		return -VKERNEL_EFAULT;
	}
	*(int *)dst = getsockopt_user_len;
	return 0;
}

int sk_getsockopt(struct sock *sk, int level, int optname,
		  sockptr_t optval, sockptr_t optlen)
{
	unsigned int choice = nondet_uint();
	sockptr_t expected_optval;
	sockptr_t expected_optlen;

	expected_optval.user = getsockopt_user_value;
	expected_optval.is_kernel = false;
	expected_optlen.user = &getsockopt_user_len;
	expected_optlen.is_kernel = false;

	__CPROVER_assert(sk == &getsockopt_model_sk,
			 "SOL_SOCKET getsockopt receives modeled sock");
	__CPROVER_assert(level == VKERNEL_SOL_SOCKET,
			 "sk_getsockopt handles only SOL_SOCKET level");
	if (optval.is_kernel) {
		expected_optval.kernel = getsockopt_kernel_value;
		expected_optval.is_kernel = true;
	}
	if (optlen.is_kernel) {
		expected_optlen.kernel = &getsockopt_kernel_len;
		expected_optlen.is_kernel = true;
	}
	__CPROVER_assert(same_sockptr(optval, expected_optval),
			 "sk_getsockopt receives the original optval sockptr");
	__CPROVER_assert(same_sockptr(optlen, expected_optlen),
			 "sk_getsockopt receives the original optlen sockptr");
	model_sk_getsockopt_calls++;
	model_last_level = level;
	model_last_optname = optname;
	__CPROVER_assume(choice <= 1);
	model_dispatch_result = choice == 0 ? 0 : -VKERNEL_EINVAL;
	return model_dispatch_result;
}

int main(void)
{
	sockptr_t optval;
	sockptr_t optlen;
	int level = nondet_int();
	int optname = nondet_int();
	int result;
	unsigned int compat_choice = nondet_uint();
	unsigned int proto_present = nondet_uint();
	unsigned int optval_kernel = nondet_uint();
	unsigned int optlen_kernel = nondet_uint();

	__CPROVER_assume(compat_choice <= 1);
	__CPROVER_assume(proto_present <= 1);
	__CPROVER_assume(optval_kernel <= 1);
	__CPROVER_assume(optlen_kernel <= 1);

	model_reset();
	if (proto_present)
		getsockopt_model_ops.getsockopt = getsockopt_model_proto_getsockopt;

	optval.user = getsockopt_user_value;
	optval.is_kernel = false;
	if (optval_kernel) {
		optval.kernel = getsockopt_kernel_value;
		optval.is_kernel = true;
	}
	optlen.user = &getsockopt_user_len;
	optlen.is_kernel = false;
	if (optlen_kernel) {
		optlen.kernel = &getsockopt_kernel_len;
		optlen.is_kernel = true;
	}

	result = do_sock_getsockopt(&getsockopt_model_socket,
				    (_Bool)compat_choice, level, optname,
				    optval, optlen);

	__CPROVER_assert(result == 0 ||
			 result == -VKERNEL_EPERM ||
			 result == -VKERNEL_EINVAL ||
			 result == -VKERNEL_EFAULT ||
			 result == -VKERNEL_EOPNOTSUPP,
			 "getsockopt returns a modeled success or errno");
	if (model_security_result) {
		__CPROVER_assert(result == model_security_result,
				 "security getsockopt error returns immediately");
		__CPROVER_assert(model_copy_calls == 0 &&
					 model_sk_getsockopt_calls == 0 &&
					 model_proto_getsockopt_calls == 0,
				 "security failure skips optlen read and protocol dispatch");
	}

	if (!model_security_result && compat_choice) {
		__CPROVER_assert(model_copy_calls == 0,
				 "compat getsockopt skips max optlen read");
	}
	if (!model_security_result && !compat_choice) {
		__CPROVER_assert(model_copy_calls == 1,
				 "non-compat getsockopt reads max optlen once");
	}

	if (!model_security_result && level == VKERNEL_SOL_SOCKET) {
		__CPROVER_assert(model_sk_getsockopt_calls == 1,
				 "SOL_SOCKET dispatches to sk_getsockopt once");
		__CPROVER_assert(model_proto_getsockopt_calls == 0,
				 "SOL_SOCKET does not call legacy protocol getsockopt");
		__CPROVER_assert(result == model_dispatch_result,
				 "SOL_SOCKET dispatch result propagates under current Kbuild config");
	}

	if (!model_security_result && level != VKERNEL_SOL_SOCKET && !proto_present) {
		__CPROVER_assert(result == -VKERNEL_EOPNOTSUPP,
				 "missing legacy getsockopt returns EOPNOTSUPP");
		__CPROVER_assert(model_sk_getsockopt_calls == 0 &&
					 model_proto_getsockopt_calls == 0,
				 "missing legacy getsockopt skips callbacks");
	}

	if (!model_security_result && level != VKERNEL_SOL_SOCKET && proto_present &&
	    (optval_kernel || optlen_kernel)) {
		__CPROVER_assert(result == -VKERNEL_EOPNOTSUPP,
				 "legacy getsockopt rejects kernel sockptr arguments");
		__CPROVER_assert(model_proto_getsockopt_calls == 0,
				 "kernel sockptr rejection skips legacy callback");
	}

	if (!model_security_result && level != VKERNEL_SOL_SOCKET && proto_present &&
	    !optval_kernel && !optlen_kernel) {
		__CPROVER_assert(model_proto_getsockopt_calls == 1,
				 "user legacy getsockopt calls protocol once");
		__CPROVER_assert(result == model_dispatch_result,
				 "legacy protocol getsockopt result propagates");
	}

	if (model_copy_failed && !compat_choice && !model_security_result) {
		__CPROVER_assert(model_sk_getsockopt_calls +
					 model_proto_getsockopt_calls <= 1,
				 "failed max optlen read still reaches at most one dispatch path");
	}

	return 0;
}
