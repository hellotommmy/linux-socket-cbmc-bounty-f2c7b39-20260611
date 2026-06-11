#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ -z "${LINUX_SRC:-}" ]]; then
  echo "LINUX_SRC must point to a Linux kernel source tree" >&2
  exit 2
fi

RUNNERS=(
  scripts/run-real-linux-socket-proof.sh
  scripts/run-real-linux-socketpair-bughunt.sh
  scripts/run-real-linux-sendmsg-control-bughunt.sh
  scripts/run-real-linux-accept-bughunt.sh
  scripts/run-real-linux-setsockopt-bughunt.sh
  scripts/run-real-linux-getsockopt-bughunt.sh
)

for runner in "${RUNNERS[@]}"; do
  echo "==> ${runner}"
  bash "${ROOT}/${runner}"
done
