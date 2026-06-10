# Amazon/AWS CBMC Notes

AWS's public CBMC work is best read as modular, harness-driven verification
rather than monolithic whole-program model checking.

Observed pattern:

- A proof directory corresponds to one entry point or small family of entry
  points.
- The harness supplies nondeterministic inputs and context-specific assumptions.
- Expensive dependencies are replaced by stubs or operational models.
- Stubs are not empty mocks: they include preconditions, postconditions, and
  assertions about how production code is allowed to call them.
- CI runs the proof set, so regressions are caught the way unit-test regressions
  are caught.

Concrete public examples:

- `awslabs/aws-c-common/verification/cbmc/proofs`
- `awslabs/aws-c-common/verification/cbmc/stubs`
- `awslabs/aws-c-common/verification/cbmc/include`
- `aws/s2n-tls/tests/cbmc/proofs`
- `aws/s2n-tls/tests/cbmc/stubs`
- `aws/s2n-tls/tests/cbmc/source`
- `aws/s2n-tls/tests/cbmc/README.md`

AWS proof directories commonly have a local `Makefile`, a harness C file, and
proof metadata such as `cbmc-proof.txt`. Shared logic is pushed into common
Makefiles/scripts, with project sources separated from proof-only sources.

This project follows that pattern for Linux `__sys_socket`:

- `scripts/run-real-linux-socket-proof.sh` invokes Kbuild on a real Linux
  source tree to generate `include/generated/*` and `net/socket.i`.
- `extract-socket-proof-slice-from-preprocessed.py` extracts the verified
  functions from that Kbuild preprocessed source.
- `real_harness_tail.c` defines the formal predicates and assertions for
  supported flags, stripped socket type, normalized fd flags, and modeled
  error/fd results.
- `goto-instrument --replace-calls` makes `sock_create` and `sock_map_fd` the
  modular proof boundary, matching the AWS style of context-sensitive stubs.
- `kernel/net/socket_cbmc_slice.c` remains only as a fast fallback regression
  path for the contracts.
- `scripts/run-real-linux-socketpair-bughunt.sh` applies the same real Kbuild
  pipeline to `__sys_socketpair`, then checks fd/file/socket lifecycle
  assertions under modeled failure injection.

Answer to the modular/context-sensitive question: AWS proofs are modular in how
they slice the codebase and schedule CI jobs, but context-sensitive in each
proof's harness and models. That is the useful combination for kernel socket
verification too.

For this bounty project, the modular boundary is proof infrastructure. It is
necessary for CBMC scalability, but it is not counted as bounty-bearing source
or specification-line work unless it appears as an explicit formal assertion.
One complete assertion counts once regardless of physical line wrapping.

Useful next imports if this grows:

- coverage jobs using `cbmc --cover location`
- `cbmc-viewer` reports for uncovered code triage
- function-pointer restriction for `struct proto_ops`
- ghost-state stubs for locking, reference counts, fd tables, and usercopy
