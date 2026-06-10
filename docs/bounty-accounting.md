# Bounty Accounting

The requested rough accounting is:

```text
bounty_units = verified_source_loc * specification_lines / 1000
```

For this repository, this is governed by `RULES.md`:

- verified source lines are counted from the real Linux source symbols when
  `--linux-src` is supplied. Fallback marker counting exists only for legacy
  local regression.
- `specification_lines` counts complete logical `__CPROVER_assert` statements
  in the `spec_files` listed in `proof.json`.
- One assertion counts as one line even when the C expression is wrapped across
  multiple physical source lines. Deliberately adding line breaks does not
  increase the metric.
- harness control flow, compatibility shims, generated code, extraction glue,
  and wrappers never count.
- boundary-model assertions count only when they are explicit formal contracts
  for the current mainline target and are listed in that target's `spec_files`.
- extra wrappers outside the current mainline target are negative bounty
  evidence, not billable work.

Run:

```sh
python3 scripts/count-proof-metrics.py \
  verification/cbmc/proofs/net_socket_sys_socket/proof.json \
  --linux-src /path/to/linux
```

This is not a legal or financial quote. It is a transparent, reproducible
workload metric that can be used to rank proof contributions.

Bug bounties are separate. A proof that finds no counterexample is engineering
progress; a reproducible, unknown upstream kernel bug needs a separate triage
record and disclosure path before any bug bounty claim.
