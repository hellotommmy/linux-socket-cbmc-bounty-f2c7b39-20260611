# Socket Bug-Hunting Notes

The bug-hunting track prioritizes real Linux socket entry points where CBMC can
exhaust fault-injection combinations that fuzzers often sample only partially.
All targets must still use real Kbuild-derived source slices and explicit
assertions.

## Current Status

`__sys_socketpair` was the first bug-hunt target because its cleanup behavior
combines two reserved fds, two sockets, two files, `put_user`, a security hook,
protocol `socketpair`, `sock_alloc_file`, `fd_install`, and `fput`.

The current profile:

- source: real `net/socket.c` from the configured Linux tree
- generated dependency: Kbuild `net/socket.i`
- runner: `scripts/run-real-linux-socketpair-bughunt.sh`
- proof metadata:
  `verification/cbmc/proofs/net_socketpair_bughunt/proof.json`
- property class: fd/file/socket resource accounting on every modeled failure
  path
- latest local result: `VERIFICATION SUCCESSFUL`, `0 of 230 failed`

This means no counterexample was found in the current bounded model. It is not a
bug bounty claim.

`____sys_sendmsg` is now the second bug-hunt target. The first bounded profile
checks the syscall-layer control-message path: `msg_controllen > INT_MAX`,
stack-vs-dynamic control buffers, `sock_kmalloc`, `copy_from_user`,
compat-cmsg conversion, `sock_kfree_s`, `sock_sendmsg_nosec`, `__sock_sendmsg`,
and clearing `MSG_INTERNAL_SENDMSG_FLAGS` before protocol send.

The current sendmsg profile:

- source: real `net/socket.c` from the configured Linux tree
- generated dependency: Kbuild `net/socket.i`
- runner: `scripts/run-real-linux-sendmsg-control-bughunt.sh`
- proof metadata:
  `verification/cbmc/proofs/net_sendmsg_control_bughunt/proof.json`
- property class: control-buffer lifetime, copy-failure cleanup, and protocol
  send flag sanitization
- latest local result: `VERIFICATION SUCCESSFUL`, `0 of 274 failed`

This also means no counterexample was found in the current bounded model. It is
not a bug bounty claim.

`do_accept` is now the third bug-hunt target. The current bounded profile checks
new socket/new file lifetime, `sock_alloc_file` failure release behavior,
security and protocol accept failures, peer-address `getname`/`move_addr_to_user`
failures, and propagation of listener type/ops into the accepted socket.

The current accept profile:

- source: real `net/socket.c` from the configured Linux tree
- generated dependency: Kbuild `net/socket.i`
- runner: `scripts/run-real-linux-accept-bughunt.sh`
- proof metadata:
  `verification/cbmc/proofs/net_accept_bughunt/proof.json`
- property class: accepted file/socket cleanup and peer-address export error
  handling
- latest local result: `VERIFICATION SUCCESSFUL`, `0 of 316 failed`

This also means no counterexample was found in the current bounded model. It is
not a bug bounty claim.

## Next Targets

1. Extend sendmsg outward to `___sys_sendmsg` and `copy_msghdr_from_user`

   Focus: control-message lengths, iovec import boundaries, `sock_kmalloc`
   cleanup, and flag sanitization.

2. `do_sock_getsockopt` and `sockptr_to_sockopt`

   Focus: user `optlen`, BPF cgroup getsockopt rewrites, protocol callbacks,
   and usercopy writeback length consistency.

3. `do_sock_setsockopt`

   Focus: `kernel_optval`, BPF rewrite outcomes, `kfree` exactly once, and
   SOL_SOCKET/custom/protocol dispatch consistency.

4. Extend accept outward to `__sys_accept4_file`

   Focus: fd reservation/install cleanup around `FD_ADD`, invalid flag
   normalization, and interaction with the proven `do_accept` cleanup contract.

## Triage Rule

Every failed CBMC run must be classified before it is called a bug:

- model bug: the harness is too strong, too weak, or has a C/CBMC artifact
- source bug candidate: the trace maps to real Linux source behavior under a
  plausible environment contract
- expected behavior: the assertion was not a valid kernel contract

Only source bug candidates get a minimization record and responsible disclosure
tracking.
