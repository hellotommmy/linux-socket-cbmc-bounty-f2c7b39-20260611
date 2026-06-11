# Linux Socket Formal Verification Trial

This directory is the product-style trial layout for the socket-layer CBMC
proofs. It is intended to live inside a Linux kernel tree at:

```text
kernel/linux/kh_common_modules/formal_verification/
```

The production kernel source stays outside this directory and is not edited by
the verification scripts. The only copied source file here is a verification
twin under `twins/`, and `make verify-twins` checks that it is byte-identical to
the corresponding production source before proofs are run.

## Layout

- `RULES.md` is the project charter and bounty accounting rulebook.
- `twins/manifest.json` maps verification twins to production source files.
- `twins/net/socket.c` is the current byte-identical twin of `net/socket.c`.
- `verification/cbmc/proofs/` contains the CBMC harness tails and proof metadata.
- `scripts/` contains extraction, sanitization, checking, and proof runners.
- `docs/` explains proof intent, bounty accounting, and bug-hunt status.

## Local Entry Points

Run from this directory in a kernel source tree:

```sh
make verify-twins
make check-specs
make proofs
make metrics
```

By default `LINUX_SRC` is the kernel root two levels above this directory. In a
separate source/build layout, pass both paths explicitly:

```sh
make proofs LINUX_SRC=/root/vkernel-linux-src LINUX_BUILD=/root/vkernel-linux-build-product
```

The proof runners use the real Linux Kbuild pipeline to generate `net/socket.i`,
then extract CBMC-compatible translation units from that preprocessed source.
Fallback slices are not bounty-bearing verified source.

## CI Shape

The GitHub workflow has a separate product-layout verification job that copies
this directory into an unpacked Linux source tree and calls the same `make`
entry points used locally. This matches the intended product pipeline:

1. Normal kernel build stage remains unchanged.
2. Verification is an independent stage under `kh_common_modules/formal_verification`.
3. The stage fails if twins drift, specifications become vacuous, or any proof
   fails.

## Accounting

The active metric is:

```text
bounty_units = verified_linux_source_loc * specification_lines / 1000
```

`specification_lines` counts complete logical `__CPROVER_assert` statements,
not physical wrapping. Wrappers, generated code, extraction glue, compatibility
shims, and non-mainline scaffolding never count.
