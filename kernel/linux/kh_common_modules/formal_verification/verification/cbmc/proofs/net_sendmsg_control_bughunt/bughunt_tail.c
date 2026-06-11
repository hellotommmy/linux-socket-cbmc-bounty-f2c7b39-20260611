/*
 * Bug-hunting harness for the real Kbuild-derived ____sys_sendmsg slice.
 *
 * The target is the syscall-layer control-buffer and flag contract: dynamic
 * control-message storage must be released on every path, usercopy failures
 * must not reach protocol send, and protocol send must not observe internal
 * sendpage flags.
 */

#include "socket_contracts_kernel_constants.h"

int nondet_int(void);
unsigned int nondet_uint(void);
unsigned long nondet_ulong(void);

#define MODEL_CTL_HEAP_MAX 128U
#define MODEL_STACK_CTL_SIZE ((int)(sizeof(struct cmsghdr) + 20U))

static struct sock model_sock;
static struct file model_file;
static struct socket model_socket;
static struct msghdr model_msg;
static struct used_address model_used_address;
static struct sockaddr_storage model_name;
static unsigned char model_user_control[MODEL_CTL_HEAP_MAX];
static unsigned char model_ctl_heap[MODEL_CTL_HEAP_MAX];

static int model_dynamic_live;
static int model_dynamic_allocs;
static int model_dynamic_frees;
static int model_dynamic_len;
static int model_malloc_failed;
static int model_copy_calls;
static int model_copy_failed;
static int model_send_calls;
static int model_nosec_send_calls;
static int model_compat_calls;
static int model_compat_failed;
static unsigned int model_observed_send_flags;
static unsigned int model_initial_msg_flags;
static unsigned int model_initial_flags;
static unsigned int model_allowed_flags;
static int model_file_nonblock;

static __kernel_size_t model_choose_controllen(void)
{
	unsigned int choice = nondet_uint();

	__CPROVER_assume(choice <= 5U);
	if (choice == 0U)
		return 0;
	if (choice == 1U)
		return 1U;
	if (choice == 2U)
		return (unsigned int)MODEL_STACK_CTL_SIZE;
	if (choice == 3U)
		return (unsigned int)MODEL_STACK_CTL_SIZE + 1U;
	if (choice == 4U)
		return MODEL_CTL_HEAP_MAX;
	return (unsigned long)VKERNEL_INT_MAX + 1UL;
}

static int model_send_result(void)
{
	unsigned int choice = nondet_uint();

	__CPROVER_assume(choice <= 2U);
	if (choice == 0U)
		return 0;
	if (choice == 1U)
		return 7;
	return -VKERNEL_EFAULT;
}

static void model_reset(void)
{
	model_sock.model_id = 1;
	model_file.f_flags = 0;
	model_socket.sk = &model_sock;
	model_socket.file = &model_file;

	model_msg.msg_name = 0;
	model_msg.msg_namelen = 0;
	model_msg.msg_inq = 0;
	model_msg.msg_control = 0;
	model_msg.msg_control_is_user = true;
	model_msg.msg_get_inq = false;
	model_msg.msg_flags = 0;
	model_msg.msg_controllen = 0;
	model_msg.msg_iocb = 0;
	model_msg.msg_ubuf = 0;

	model_used_address.name_len = 0;

	model_dynamic_live = 0;
	model_dynamic_allocs = 0;
	model_dynamic_frees = 0;
	model_dynamic_len = 0;
	model_malloc_failed = 0;
	model_copy_calls = 0;
	model_copy_failed = 0;
	model_send_calls = 0;
	model_nosec_send_calls = 0;
	model_compat_calls = 0;
	model_compat_failed = 0;
	model_observed_send_flags = 0;
	model_initial_msg_flags = 0;
	model_initial_flags = 0;
	model_allowed_flags = 0;
	model_file_nonblock = 0;
}

static void *model_alloc_control(int len)
{
	unsigned int fail = nondet_uint();

	__CPROVER_assert(len > 0, "control allocation length is positive");
	__CPROVER_assert((unsigned int)len <= MODEL_CTL_HEAP_MAX,
			 "control allocation fits the bounded heap model");
	__CPROVER_assert(!model_dynamic_live,
			 "control allocation does not overwrite live storage");
	__CPROVER_assume(fail <= 1U);
	if (fail) {
		model_malloc_failed++;
		return 0;
	}

	model_dynamic_live = 1;
	model_dynamic_allocs++;
	model_dynamic_len = len;
	return model_ctl_heap;
}

void *sock_kmalloc(struct sock *sk, int len, gfp_t priority)
{
	(void)priority;
	__CPROVER_assert(sk == &model_sock,
			 "sock_kmalloc uses the modeled socket state");
	return model_alloc_control(len);
}

void sock_kfree_s(struct sock *sk, void *mem, int size)
{
	__CPROVER_assert(sk == &model_sock,
			 "sock_kfree_s uses the modeled socket state");
	__CPROVER_assert(mem == model_ctl_heap,
			 "sock_kfree_s releases the modeled control buffer");
	__CPROVER_assert(model_dynamic_live,
			 "sock_kfree_s does not double-free control storage");
	__CPROVER_assert(size == model_dynamic_len,
			 "sock_kfree_s receives the allocation length");
	model_dynamic_live = 0;
	model_dynamic_frees++;
}

int copy_from_user(void *to, const void *from, unsigned long n)
{
	unsigned int fail = nondet_uint();

	model_copy_calls++;
	__CPROVER_assert(to != 0 || n == 0,
			 "copy_from_user has a destination for non-empty copy");
	if (to == model_ctl_heap)
		__CPROVER_assert(model_dynamic_live &&
					 n <= (unsigned long)model_dynamic_len,
				 "copy_from_user stays within dynamic control buffer");
	if (n == 0)
		return 0;
	if (from == 0) {
		model_copy_failed++;
		return 1;
	}

	__CPROVER_assume(fail <= 1U);
	if (fail) {
		model_copy_failed++;
		return 1;
	}
	return 0;
}

int cmsghdr_from_user_compat_to_kern(struct msghdr *kmsg, struct sock *sk,
				     unsigned char *stackbuf, int stackbuf_size)
{
	unsigned int choice = nondet_uint();
	void *allocated;

	model_compat_calls++;
	__CPROVER_assert(kmsg == &model_msg,
			 "compat cmsg conversion receives modeled msghdr");
	__CPROVER_assert(sk == &model_sock,
			 "compat cmsg conversion receives modeled sock");
	__CPROVER_assert(stackbuf != 0 && stackbuf_size == MODEL_STACK_CTL_SIZE,
			 "compat cmsg conversion receives stack control buffer");
	__CPROVER_assume(choice <= 5U);

	if (choice == 0U) {
		model_compat_failed++;
		return -VKERNEL_EFAULT;
	}
	if (choice == 1U) {
		model_compat_failed++;
		return -VKERNEL_EINVAL;
	}
	if (choice == 2U) {
		allocated = model_alloc_control(MODEL_STACK_CTL_SIZE + 1);
		if (allocated != 0)
			sock_kfree_s(sk, allocated, MODEL_STACK_CTL_SIZE + 1);
		model_compat_failed++;
		return -VKERNEL_EFAULT;
	}
	if (choice == 3U) {
		kmsg->msg_control = stackbuf;
		kmsg->msg_control_is_user = false;
		kmsg->msg_controllen = (unsigned int)MODEL_STACK_CTL_SIZE;
		return 0;
	}
	if (choice == 4U) {
		allocated = model_alloc_control(MODEL_STACK_CTL_SIZE + 1);
		if (allocated == 0) {
			model_compat_failed++;
			return -VKERNEL_ENOMEM;
		}
		kmsg->msg_control = allocated;
		kmsg->msg_control_is_user = false;
		kmsg->msg_controllen = (unsigned int)MODEL_STACK_CTL_SIZE + 1U;
		return 0;
	}

	allocated = model_alloc_control((int)MODEL_CTL_HEAP_MAX);
	if (allocated == 0) {
		model_compat_failed++;
		return -VKERNEL_ENOMEM;
	}
	kmsg->msg_control = allocated;
	kmsg->msg_control_is_user = false;
	kmsg->msg_controllen = MODEL_CTL_HEAP_MAX;
	return 0;
}

static void model_record_send(struct socket *sock, struct msghdr *msg)
{
	__CPROVER_assert(sock == &model_socket,
			 "send receives modeled socket");
	__CPROVER_assert(msg == &model_msg,
			 "send receives modeled msghdr");
	__CPROVER_assert((msg->msg_flags & VKERNEL_MSG_INTERNAL_SENDMSG_FLAGS) == 0U,
			 "protocol send does not observe internal sendmsg flags");
	if (model_file_nonblock)
		__CPROVER_assert((msg->msg_flags & VKERNEL_MSG_DONTWAIT) != 0U,
				 "protocol send observes MSG_DONTWAIT for nonblocking file");
	if (msg->msg_controllen != 0)
		__CPROVER_assert(!msg->msg_control_is_user,
				 "protocol send sees kernel-owned control buffer");
	model_observed_send_flags = msg->msg_flags;
}

int sock_sendmsg_nosec(struct socket *sock, struct msghdr *msg)
{
	model_nosec_send_calls++;
	model_record_send(sock, msg);
	return model_send_result();
}

int __sock_sendmsg(struct socket *sock, struct msghdr *msg)
{
	model_send_calls++;
	model_record_send(sock, msg);
	return model_send_result();
}

int memcmp(const void *s1, const void *s2, unsigned long n)
{
	unsigned int equal = nondet_uint();

	__CPROVER_assert(s1 != 0 && s2 != 0,
			 "memcmp receives non-null address buffers");
	__CPROVER_assert(n <= sizeof(struct sockaddr_storage),
			 "memcmp stays within sockaddr_storage");
	__CPROVER_assume(equal <= 1U);
	return equal ? 0 : 1;
}

void *memcpy(void *dest, const void *src, unsigned long n)
{
	__CPROVER_assert(dest != 0 && src != 0,
			 "memcpy receives non-null address buffers");
	__CPROVER_assert(n <= sizeof(struct sockaddr_storage),
			 "memcpy stays within sockaddr_storage");
	return dest;
}

static unsigned int expected_send_flags(void)
{
	unsigned int expected;

	expected = model_initial_flags |
		   (model_initial_msg_flags & model_allowed_flags);
	expected &= ~VKERNEL_MSG_INTERNAL_SENDMSG_FLAGS;
	if (model_file_nonblock)
		expected |= VKERNEL_MSG_DONTWAIT;
	return expected;
}

int main(void)
{
	unsigned int control_user_choice = nondet_uint();
	unsigned int use_name = nondet_uint();
	unsigned int use_used_address = nondet_uint();
	unsigned int same_address = nondet_uint();
	struct used_address *used_address_ptr = 0;
	int result;

	model_reset();
	__CPROVER_assume(control_user_choice <= 1U);
	__CPROVER_assume(use_name <= 1U);
	__CPROVER_assume(use_used_address <= 1U);
	__CPROVER_assume(same_address <= 1U);

	model_initial_flags = nondet_uint();
	model_initial_msg_flags = nondet_uint();
	model_allowed_flags = nondet_uint();
	model_file_nonblock = nondet_uint() != 0U;

	model_file.f_flags = model_file_nonblock ? VKERNEL_O_NONBLOCK : 0;
	model_msg.msg_flags = model_initial_msg_flags;
	model_msg.msg_controllen = model_choose_controllen();
	model_msg.msg_control_user =
		control_user_choice ? (void *)model_user_control : (void *)0;

	if (use_name) {
		model_msg.msg_name = &model_name;
		model_msg.msg_namelen = sizeof(struct sockaddr_storage);
	} else {
		model_msg.msg_name = 0;
		model_msg.msg_namelen = 0;
	}

	if (use_used_address) {
		used_address_ptr = &model_used_address;
		model_used_address.name_len =
			same_address ? (unsigned int)model_msg.msg_namelen : 0U;
	}

	result = ____sys_sendmsg(&model_socket, &model_msg, model_initial_flags,
				 used_address_ptr, model_allowed_flags);

	__CPROVER_assert(model_dynamic_live == 0,
			 "sendmsg leaves no live dynamic control buffer");
	__CPROVER_assert(model_dynamic_allocs == model_dynamic_frees,
			 "sendmsg releases each successful control allocation exactly once");
	__CPROVER_assert(model_send_calls + model_nosec_send_calls <= 1,
			 "sendmsg reaches at most one protocol send path");

	if (model_msg.msg_controllen == (unsigned long)VKERNEL_INT_MAX + 1UL) {
		__CPROVER_assert(result == -VKERNEL_ENOBUFS,
				 "oversized control length returns -ENOBUFS");
		__CPROVER_assert(model_send_calls == 0 && model_nosec_send_calls == 0,
				 "oversized control length skips protocol send");
		__CPROVER_assert(model_copy_calls == 0,
				 "oversized control length skips usercopy");
	}

	if (model_copy_failed) {
		__CPROVER_assert(result == -VKERNEL_EFAULT,
				 "control usercopy failure returns -EFAULT");
		__CPROVER_assert(model_send_calls == 0 && model_nosec_send_calls == 0,
				 "control usercopy failure skips protocol send");
	}

	if (model_malloc_failed && model_dynamic_allocs == model_dynamic_frees) {
		__CPROVER_assert(model_send_calls == 0 && model_nosec_send_calls == 0,
				 "control allocation failure skips protocol send");
	}

	if (model_send_calls + model_nosec_send_calls == 1)
		__CPROVER_assert(model_observed_send_flags == expected_send_flags(),
				 "protocol send observes sanitized sendmsg flags");

	return 0;
}
