# Product Layout Trial

This trial follows the requested national-certification material layout:

```text
kernel/linux/kh_common_modules/formal_verification/
```

The directory is self-contained for proof execution, but it does not replace or
edit production kernel source. `LINUX_SRC` identifies the production source tree,
and `LINUX_BUILD` identifies the Kbuild output directory.

## Required Gate Order

1. `make verify-twins` checks that every listed twin exactly matches the
   corresponding production source file.
2. `make check-specs` rejects vacuous or tautological assertion patterns.
3. `make proofs` runs the six current real-source socket proofs through Kbuild
   generated `net/socket.i`.
4. `make metrics` reports `verified_linux_source_loc * specification_lines /
   1000` for each accepted proof.

## Current Scope

The current verified production source is `net/socket.c`, starting with these
socket interface paths:

- `__sys_socket_create`, `update_socket_protocol`, `__sys_socket`
- `__sys_socketpair`
- `____sys_sendmsg`
- `do_accept`
- `do_sock_setsockopt`
- `do_sock_getsockopt`

The twin file is used only to document and freeze the exact source snapshot for
review. The proofs themselves still extract from the production Kbuild
preprocessed source, not from the twin.

The public GitHub CI unpacks a distribution `linux-source` package instead of
carrying a full product kernel tree in the repository. For that CI-only trial,
the workflow refreshes `twins/net/socket.c` from the unpacked source before
calling `make`; in the product repository the twin should already be committed
with the same version as production `net/socket.c`.

## Non-Goals

- No toy source is accepted as verified production code.
- No wrapper is counted as bounty-bearing work.
- No physical line wrapping is counted as extra specification complexity.
- No proof is accepted if its assertions are true only because the harness made
  the relevant path impossible.
