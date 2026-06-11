# Proof Property Meaning

This document explains what the current CBMC properties mean in engineering
terms. A property is useful only when it constrains real Linux socket behavior
under a documented proof boundary. Assertions that are true by syntax alone,
or true only because the harness assumed away the interesting path, are not
accepted specification work.

Notation:

- \(res\) is the return value of the verified Linux entry point.
- \(calls(f)\) is a ghost counter maintained by the proof model for boundary
  function \(f\).
- \(live(x)\) means the modeled resource \(x\) is still owned/live at return.
- \(dispatch\_ret\), \(security\_ret\), and similar names are nondeterministic
  model results returned by boundary functions.

## Meaningful Property Rule

A bounty-bearing assertion should satisfy at least one of these:

- It constrains the return value on a real branch of the source.
- It constrains whether a real boundary call is reached.
- It constrains arguments passed from real source code to a boundary call.
- It constrains resource lifetime across success and failure paths.
- It constrains user/kernel pointer routing or flag normalization.

Rejected examples:

```c
__CPROVER_assert(1, "always true");
__CPROVER_assert(x == x, "self equality");
__CPROVER_assert(a || !a, "excluded middle");
__CPROVER_assume(false);
```

Literal false assertions are allowed only for intentional unreachable states,
for example a final impossible enum/default case, and the message must identify
the unreachable contract. They are not a way to inflate specification count.

## `__sys_socket`

Plain meaning: socket creation must reject unknown creation flags before doing
work; valid flags must be stripped and normalized before the fd layer sees
them; errors from the creation and fd-mapping layers must propagate exactly.

\[
invalid\_flags(type)
\Rightarrow
res=-EINVAL \land calls(sock\_create)=0 \land calls(sock\_map\_fd)=0
\]

This catches bugs where unsupported flag bits accidentally reach
`sock_create()` or allocate a socket before the syscall returns `-EINVAL`.

\[
valid\_flags(type)
\Rightarrow
calls(sock\_create)=1
\land create.type=(type \mathbin{\&} SOCK\_TYPE\_MASK)
\]

This catches bugs where `SOCK_CLOEXEC` or `SOCK_NONBLOCK` leak into the socket
type argument instead of being treated as fd flags.

\[
sock\_create\_ret=0
\Rightarrow
calls(sock\_map\_fd)=1
\land map.flags=normalize(type)
\land res=sock\_map\_fd\_ret
\]

This catches fd flag normalization regressions and wrong return propagation.

## `__sys_socketpair`

Plain meaning: socketpair has many partial-success states. Every modeled
failure path must release all reserved fds, files, and sockets. Success must
install exactly two fds and leave exactly two live file-owned sockets.

\[
res=0
\Rightarrow
installed\_fds=2
\land live\_files=2
\land live\_sockets=2
\land reserved\_fds=0
\]

\[
res<0
\Rightarrow
installed\_fds=0
\land live\_files=0
\land live\_sockets=0
\land reserved\_fds=0
\]

These are not algebraic tautologies: the counters are changed only by modeled
Linux boundary calls such as `get_unused_fd_flags`, `sock_alloc_file`,
`fd_install`, `fput`, and `sock_release`. A missed cleanup call produces a
counterexample.

## `____sys_sendmsg`

Plain meaning: the sendmsg path must not leak dynamically allocated control
buffers, must not send after copy/conversion failures, and must strip internal
send flags before crossing into protocol send.

\[
dynamic\_allocs=dynamic\_frees \land live\_dynamic\_control=0
\]

This catches leaks and double-live states around `sock_kmalloc`,
`copy_from_user`, compat conversion, and `sock_kfree_s`.

\[
copy\_failed \lor compat\_convert\_failed
\Rightarrow
calls(send)=0
\]

This catches bugs where partially copied ancillary data could still be sent.

\[
calls(send)>0
\Rightarrow
(msg.flags \mathbin{\&} MSG\_INTERNAL\_SENDMSG\_FLAGS)=0
\land msg.control\_is\_user=false
\]

This catches flag-sanitization and user/kernel control-buffer routing bugs at
the protocol-send boundary.

## `do_accept`

Plain meaning: accepting a connection creates a new socket and often a new
file. Every failure after partial allocation must release the accepted object
exactly once, while the listening socket/file remain live. Peer-address export
failures must also clean up the accepted file.

\[
\neg is\_socket(input)
\Rightarrow
res=-ENOTSOCK \land calls(sock\_alloc)=0
\]

This catches accidental allocation on nonsocket inputs.

\[
res<0
\Rightarrow
live\_new\_files=0 \land live\_new\_sockets=0
\]

\[
file\_allocated \land res<0
\Rightarrow
calls(fput)=1
\]

These catch leaks and double-release mistakes on security failure, protocol
accept failure, `getname` failure, and `move_addr_to_user` failure paths.

\[
res=0
\Rightarrow
new.type=listen.type
\land new.ops=listen.ops
\land calls(proto\_accept)=1
\]

This catches regressions where the accepted socket is not initialized from the
listener before protocol accept.

The proof supports both callback ABIs observed in real Kbuild output:

\[
proto\_arg\_ABI:
arg.flags = arg_0.flags \lor listen.file.f\_flags
\]

\[
legacy\_ABI:
proto.flags = file\_flags \lor listen.file.f\_flags
\land kern=false
\]

This catches version-specific flag propagation mistakes without pretending that
one Linux version's ABI exists in another.

## `do_sock_setsockopt`

Plain meaning: invalid lengths and security failures must stop before dispatch;
valid calls must dispatch to exactly the correct SOL_SOCKET or protocol path;
missing protocol callbacks must return `-EOPNOTSUPP`. In the current defconfig
profile, the BPF hook preprocesses to zero, so cleanup must only free NULL.

\[
optlen<0
\Rightarrow
res=-EINVAL
\land calls(security)=0
\land calls(sock\_setsockopt)=0
\land calls(proto\_setsockopt)=0
\]

This catches bugs where negative lengths reach security or protocol code.

\[
security\_ret\neq0
\Rightarrow
res=security\_ret
\land calls(dispatch)=0
\land calls(kfree)=0
\]

This catches security short-circuit regressions.

\[
level=SOL\_SOCKET \land \neg custom
\Rightarrow
calls(sock\_setsockopt)=1
\land calls(proto\_setsockopt)=0
\]

\[
(level\neq SOL\_SOCKET \lor custom) \land proto\_present
\Rightarrow
calls(proto\_setsockopt)=1
\]

These catch wrong dispatch between common socket options and protocol-specific
handlers.

\[
(level\neq SOL\_SOCKET \lor custom) \land \neg proto\_present
\Rightarrow
res=-EOPNOTSUPP
\]

This catches missing-callback behavior regressions.

## `do_sock_getsockopt`

Plain meaning: security failures must stop before reading user optlen or
dispatching; non-compat calls read max optlen exactly once; SOL_SOCKET goes to
`sk_getsockopt`; legacy protocol getsockopt must never receive kernel
`sockptr_t` arguments.

\[
security\_ret\neq0
\Rightarrow
res=security\_ret
\land calls(copy\_from\_sockptr)=0
\land calls(dispatch)=0
\]

This catches side effects after security denial.

\[
\neg compat \land security\_ret=0
\Rightarrow
calls(copy\_from\_sockptr)=1
\]

\[
compat \land security\_ret=0
\Rightarrow
calls(copy\_from\_sockptr)=0
\]

This catches compat/non-compat optlen handling regressions.

\[
level=SOL\_SOCKET
\Rightarrow
calls(sk\_getsockopt)=1
\land calls(proto\_getsockopt)=0
\]

\[
level\neq SOL\_SOCKET \land proto\_present
\land (optval.is\_kernel \lor optlen.is\_kernel)
\Rightarrow
res=-EOPNOTSUPP
\land calls(proto\_getsockopt)=0
\]

This catches kernel pointer leakage into the old `char *`/`int *` protocol
callback ABI.

## Current Limitations

These properties are bounded and modular:

- They prove the extracted real source under the harness's modeled environment,
  not the entire Linux kernel.
- They do not currently claim BPF-enabled getsockopt/setsockopt behavior,
  because the current defconfig Kbuild output preprocesses those hooks away.
- They do not replace fuzzing or runtime testing. They exhaust the modeled
  branch/failure combinations inside each proof boundary.
