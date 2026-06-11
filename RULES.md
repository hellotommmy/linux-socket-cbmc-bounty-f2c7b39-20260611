# Project Rules

This file is the project charter. Do not violate it.

## Mission

Find and prove real Linux kernel socket-layer properties with CBMC, using the
kernel source and the kernel build pipeline artifacts that production builds
actually produce. The first area is `net/socket.c`; bug-finding value is higher
than merely increasing proof count.

## Source Authenticity

- Verified code must come from a real Linux source tree plus Kbuild-generated
  dependencies such as generated headers and `net/socket.i`.
- Toy rewrites, hand-copied stand-ins, and unrelated wrappers are not source
  under verification.
- Sanitizers and extractors may adapt Kbuild preprocessed output for the CBMC C
  frontend, but every rewrite must be narrow, documented, and traceable to the
  original preprocessed source.
- Fallback slices may exist only for fast regression of proof infrastructure.
  They cannot be reported as bounty-bearing verified source.

## Bounty Accounting

- Workload metric:

  ```text
  bounty_units = verified_linux_source_loc * specification_lines / 1000
  ```

- `verified_linux_source_loc` counts only real Linux source symbols, normally
  from `net/socket.c` with `scripts/count-proof-metrics.py --linux-src`.
- `specification_lines` counts complete logical `__CPROVER_assert` statements.
  One assertion counts as one specification line even if its C expression is
  physically wrapped across multiple source lines.
- Do not add line breaks to inflate accounting. Physical line count is not the
  metric; logical specification statements are.
- Harness control flow, compatibility shims, extraction glue, generated code,
  and wrappers never count.
- Boundary-model assertions count only when they are explicit formal contracts
  for the current mainline target and are listed in that target's `spec_files`.
- No wrapper can be counted as work. Extra wrappers outside the current mainline
  target are negative bounty evidence and must be removed or justified.
- A successful proof with no bug is useful engineering progress, but it is not a
  bug bounty claim. Unknown, reproducible upstream bugs get a separate triage
  record and responsible disclosure path.

## Proof Acceptance

- CBMC built-in checks are necessary but insufficient. Every accepted target
  needs explicit formal contracts or assertions about socket-layer behavior.
- Proofs must run in CI or be ready to run in CI with the same source pipeline.
- A proof is accepted only when CBMC, the extraction scripts, and the Kbuild
  source provenance checks all agree.
- Over-assuming away the interesting path is a proof failure. Assumptions must
  model documented kernel/environment behavior and should be weaker than the
  property being proved.
- Tautologies, self-equalities, constant-true assertions, and assertions that
  are true only because an impossible assumption removed the path are not
  specification work and must not be counted.
- Each accepted property must be tied to at least one real source behavior:
  return value, branch reachability, boundary-call argument, resource lifetime,
  pointer class, flag normalization, or cleanup ordering.
- Literal false assertions are allowed only for intentional unreachable states
  whose message documents the impossible state being excluded.
- `docs/proof-property-meaning.md` is the current human-readable map from
  assertions to the bug classes they are meant to prevent.

## Agent Mechanism

Inspired by Agent Hunt (`arXiv:2603.06737`):

- Treat each target as a proof obligation or bug hypothesis with a clear owner,
  target function, source provenance, property, and current status.
- Agents may propose sub-targets, but the mainline target must remain visible.
  Do not drift into unrelated wrappers or low-value scaffolding.
- Accepted work must be machine-checked. Progress reports without a checker
  result are notes, not collected work.
- Use guard scripts and metrics before committing. Frequent commit/push cycles
  are preferred over large untracked piles.
- Do not rewrite another agent's work item, assumptions, or proof boundary
  silently. Record the reason for any boundary change.

Inspired by the long-running proof-checker loop in `arXiv:2601.03298`:

- Keep a tight loop between code changes and CBMC results.
- Maintain a small, stable rule file and status documents so agents do not lose
  the project intent when context changes.
- Prefer focused prompts and focused targets. A request to finish one target
  does not suspend these rules.
- No "admit" analogue: disabled assertions, vacuous assumptions, and
  checker-bypassing scripts must be called out as incomplete.
- Track dependency and status information so blocked properties become the next
  useful targets instead of hidden debt.

## Current Target Order

1. `__sys_socket` real-source proof and CI integration.
2. `__sys_socketpair` fd/file/socket lifetime bug hunt.
3. `____sys_sendmsg` and related message/control-buffer bounds.
4. `do_sock_getsockopt` and `do_sock_setsockopt` sockptr/BPF length contracts.
5. `do_accept` and `move_addr_to_user` fd cleanup and usercopy bounds.

## References

- Agent Hunt: Bounty Based Collaborative Autoformalization With LLM Agents,
  https://arxiv.org/abs/2603.06737
- 130k Lines of Formal Topology in Two Weeks: Simple and Cheap
  Autoformalization for Everyone?, https://arxiv.org/abs/2601.03298
