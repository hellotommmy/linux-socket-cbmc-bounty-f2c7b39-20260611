# Socket Bug-Hunting Notes

The bug-hunting track prioritizes real Linux socket entry points where CBMC can
exhaust fault-injection combinations that fuzzers often sample only partially.
All targets must still use real Kbuild-derived source slices and explicit
assertions.

## Current Status

`__sys_socketpair` is the first bug-hunt target because its cleanup behavior
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

## Next Targets

1. `____sys_sendmsg`, `___sys_sendmsg`, and `copy_msghdr_from_user`

   Focus: control-message lengths, iovec import boundaries, `sock_kmalloc`
   cleanup, and flag sanitization.

2. `do_sock_getsockopt` and `sockptr_to_sockopt`

   Focus: user `optlen`, BPF cgroup getsockopt rewrites, protocol callbacks,
   and usercopy writeback length consistency.

3. `do_sock_setsockopt`

   Focus: `kernel_optval`, BPF rewrite outcomes, `kfree` exactly once, and
   SOL_SOCKET/custom/protocol dispatch consistency.

4. `do_accept`, `__sys_accept4_file`, and `move_addr_to_user`

   Focus: new-file cleanup after partial success, address length truncation,
   and fd installation ordering.

## Triage Rule

Every failed CBMC run must be classified before it is called a bug:

- model bug: the harness is too strong, too weak, or has a C/CBMC artifact
- source bug candidate: the trace maps to real Linux source behavior under a
  plausible environment contract
- expected behavior: the assertion was not a valid kernel contract

Only source bug candidates get a minimization record and responsible disclosure
tracking.
