# verification_kernel

CBMC-based formal verification scaffold for Linux kernel socket entry points.
The governing rules are in `RULES.md`: real Linux source only, Kbuild pipeline
provenance, explicit formal specifications, and no wrapper code counted as
bounty work.

The first proof targets the Linux `net/socket.c` `__sys_socket` path. The main
runner uses a real Linux source tree and Kbuild-generated artifacts
(`include/generated/*`, arch generated headers, and `net/socket.i`) before CBMC
is invoked. The proof slice is extracted from that preprocessed Kbuild output,
then CBMC replaces the proof-boundary calls with explicit socket contracts. It
verifies the source-level control and data-flow around:

- accepted and rejected `SOCK_*` creation flags
- stripping `type` to `SOCK_TYPE_MASK` before `sock_create`
- default `update_socket_protocol` behavior
- propagation of `sock_create` errors
- `sock_map_fd` being reached only after successful socket creation
- fd mapping flags being normalized and masked to `O_CLOEXEC | O_NONBLOCK`

This is intentionally modeled in the style used by AWS CBMC projects: a small
entry-point proof with a harness, source-under-verification, environment models,
and CI integration. Built-in CBMC checks are enabled, but the proof value comes
from explicit assertions in `verification/cbmc/proofs/net_socket_sys_socket`.

The second target is a bug-hunting proof for real `__sys_socketpair`, focused on
fd/file/socket lifetime cleanup across intermediate failures. It currently finds
no counterexample in the bounded resource profile, which is useful coverage but
not a bug bounty claim.

## Layout

```text
kernel/net/socket_cbmc_slice.c                  Experimental fallback slice
verification/cbmc/include/kernel_compat.h       Kernel/CBMC compatibility layer
verification/cbmc/include/socket_contracts.h    Formal socket predicates
verification/cbmc/include/socket_model.h        Model instrumentation API
verification/cbmc/source/socket_models.c        Operational models/stubs
verification/cbmc/proofs/net_socket_sys_socket  Harnesses and proof metadata
scripts/run-real-linux-socket-proof.sh          Real Linux/Kbuild proof runner
scripts/run-real-linux-socketpair-bughunt.sh    Real Linux socketpair bug hunt
scripts/extract-socket-proof-slice-from-preprocessed.py
                                                Extract proof slice from socket.i
scripts/extract-socketpair-bughunt-slice-from-preprocessed.py
                                                Extract socketpair bug-hunt slice
scripts/sanitize-kernel-preprocessed-for-cbmc.py
                                                CBMC frontend compatibility pass
scripts/run-proof.sh                            Run one proof variant
scripts/run-all-proofs.sh                       Run every configured variant
scripts/count-proof-metrics.py                  Bounty accounting helper
```

## Run

Install CBMC and kernel build dependencies on Linux or WSL, point `LINUX_SRC`
to a Linux source tree, then:

```sh
LINUX_SRC=/path/to/linux \
LINUX_BUILD=$PWD/build/linux-x86_64 \
ARCH=x86_64 \
CC=gcc \
bash scripts/run-real-linux-socket-proof.sh
```

Run the socketpair resource-lifetime bug hunt:

```sh
LINUX_SRC=/path/to/linux \
LINUX_BUILD=$PWD/build/linux-x86_64 \
ARCH=x86_64 \
CC=gcc \
bash scripts/run-real-linux-socketpair-bughunt.sh
```

The legacy slice proof is still available for quick local regression of the
contracts and models:

```sh
bash scripts/run-all-proofs.sh
python3 scripts/count-proof-metrics.py \
  verification/cbmc/proofs/net_socket_sys_socket/proof.json \
  --linux-src /path/to/linux
```

The CI workflow in `.github/workflows/cbmc.yml` installs `linux-source`, runs
Kbuild to produce `net/socket.i`, and then runs the real-source CBMC proof.

Current real-source accounting on Ubuntu `linux-source-7.0.0`, using logical
specification lines and excluding wrapper/model/glue line breaks:

```text
net_socket_sys_socket:
  verified_source_loc = 33
  specification_lines = 18
  bounty_units = 0.594

net_socketpair_bughunt:
  verified_source_loc = 67
  specification_lines = 42
  bounty_units = 2.814
```

If you have a Linux source tree locally, check that the verified slice still
matches upstream before claiming source provenance:

```sh
python3 scripts/check-socket-slice-origin.py \
  --upstream /path/to/linux/net/socket.c
```

## AWS CBMC Pattern

AWS public repositories such as `awslabs/aws-c-common` and `aws/s2n-tls` keep
CBMC proofs under dedicated verification directories, with one leaf proof per
entry point. Their proofs are modular at the proof boundary: each proof has its
own harness and replaces expensive or irrelevant dependencies with models and
contracts. They are also context-sensitive inside that boundary: the harness and
stubs encode the calling context, valid nondeterministic inputs, and the abstract
behavior expected from dependencies.

Useful references:

- https://github.com/awslabs/aws-c-common
- https://github.com/aws/s2n-tls/tree/main/tests/cbmc
- https://model-checking.github.io/cbmc-training/projects.html
- https://www.amazon.science/publications/model-checking-boot-code-from-aws-data-centers
