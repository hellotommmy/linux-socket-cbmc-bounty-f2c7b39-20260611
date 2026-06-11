FV_ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
LINUX_SRC ?= $(abspath $(FV_ROOT)/../..)
LINUX_BUILD ?= $(FV_ROOT)/build/linux-kbuild
ARCH ?= x86_64
CC ?= gcc
JOBS ?= $(shell nproc 2>/dev/null || echo 2)

PROOF_JSONS := $(sort $(wildcard $(FV_ROOT)/verification/cbmc/proofs/*/proof.json))

.PHONY: all verify check-specs verify-twins proofs metrics clean

all: verify

verify: proofs metrics

check-specs:
	cd "$(FV_ROOT)" && python3 scripts/check-spec-meaningfulness.py --self-test
	cd "$(FV_ROOT)" && python3 scripts/check-spec-meaningfulness.py

verify-twins:
	cd "$(FV_ROOT)" && python3 scripts/verify_twins.py --linux-src "$(LINUX_SRC)"

proofs: verify-twins check-specs
	cd "$(FV_ROOT)" && LINUX_SRC="$(LINUX_SRC)" LINUX_BUILD="$(LINUX_BUILD)" ARCH="$(ARCH)" CC="$(CC)" JOBS="$(JOBS)" bash scripts/run_product_proofs.sh

metrics:
	cd "$(FV_ROOT)" && for proof in $(PROOF_JSONS); do \
		python3 scripts/count-proof-metrics.py "$$proof" --linux-src "$(LINUX_SRC)"; \
	done

clean:
	rm -rf "$(FV_ROOT)/build"
