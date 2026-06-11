#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROOF_NAME="${1:-net_socket_sys_socket}"
VARIANT="${2:-linux_generic}"
CBMC_BIN="${CBMC:-cbmc}"

if [[ "${PROOF_NAME}" != "net_socket_sys_socket" ]]; then
  echo "unknown proof: ${PROOF_NAME}" >&2
  exit 2
fi

DEFINES=()
case "${VARIANT}" in
  linux_generic)
    ;;
  arch_distinct_nonblock)
    DEFINES+=("-DSOCK_NONBLOCK=16384" "-DO_NONBLOCK=2048")
    ;;
  *)
    echo "unknown variant: ${VARIANT}" >&2
    exit 2
    ;;
esac

OUT_DIR="${ROOT}/build/proofs/${PROOF_NAME}/${VARIANT}"
mkdir -p "${OUT_DIR}"

CMD=(
  "${CBMC_BIN}"
  --function main
  --object-bits 12
  --unwind 1
  --bounds-check
  --pointer-check
  --signed-overflow-check
  --unsigned-overflow-check
  --conversion-check
  --div-by-zero-check
  --pointer-overflow-check
  --trace
  --stop-on-fail
  -I "${ROOT}/verification/cbmc/include"
  -DSOCKET_MODEL_PROVIDE_KERNEL_SYMBOLS
  "${DEFINES[@]}"
  "${ROOT}/kernel/net/socket_cbmc_slice.c"
  "${ROOT}/verification/cbmc/source/socket_models.c"
  "${ROOT}/verification/cbmc/proofs/${PROOF_NAME}/harness.c"
)

echo "Running ${PROOF_NAME}/${VARIANT}"
"${CMD[@]}" | tee "${OUT_DIR}/cbmc.txt"

grep -q "VERIFICATION SUCCESSFUL" "${OUT_DIR}/cbmc.txt"
