#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

bash "${ROOT}/scripts/run-proof.sh" net_socket_sys_socket linux_generic
bash "${ROOT}/scripts/run-proof.sh" net_socket_sys_socket arch_distinct_nonblock
