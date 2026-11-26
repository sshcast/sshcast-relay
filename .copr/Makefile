SHELL := /bin/bash
spec ?= sshcast-relay.spec
outdir ?= .

SPEC_ABS := $(abspath $(spec))
OUTDIR_ABS := $(abspath $(outdir))
REPO_ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/..)

.PHONY: srpm

srpm:
	@set -euo pipefail; \
	if ! command -v cargo >/dev/null 2>&1 || ! command -v git >/dev/null 2>&1 || ! command -v rpmbuild >/dev/null 2>&1; then \
		dnf -y install cargo git-core rpm-build; \
	fi; \
	SPEC="$(SPEC_ABS)"; \
	if [ -z "$$SPEC" ] || [ -d "$$SPEC" ]; then SPEC="$(REPO_ROOT)/sshcast-relay.spec"; fi; \
	OUTDIR="$(OUTDIR_ABS)"; \
	ROOT="$(REPO_ROOT)"; \
	VER=$$(grep -E '^Version:' "$$SPEC" | awk '{print $$2}'); \
	if [ -z "$$VER" ]; then echo "Failed to parse Version from $$SPEC" >&2; exit 1; fi; \
	if [ ! -f "$$ROOT/sshcast-proto/Cargo.toml" ]; then \
		git -C "$$ROOT" submodule update --init --recursive; \
	fi; \
	mkdir -p "$$OUTDIR"; \
	STAGE=$$(mktemp -d); \
	trap 'rm -rf "$$STAGE"' EXIT; \
	STAGE_SRC="$$STAGE/sshcast-relay-$$VER"; \
	mkdir -p "$$STAGE_SRC"; \
	tar --exclude='.git' --exclude='./target' --exclude='sshcast-proto/target' --exclude='./vendor' --exclude='*.rpm' --exclude='*.src.rpm' -cf - -C "$$ROOT" . | tar -xf - -C "$$STAGE_SRC"; \
	(cd "$$STAGE_SRC" && cargo vendor --locked vendor >/dev/null); \
	mkdir -p "$$STAGE_SRC/.cargo"; \
	printf '[source.crates-io]\nreplace-with = "vendored-sources"\n\n[source.vendored-sources]\ndirectory = "vendor"\n' > "$$STAGE_SRC/.cargo/config.toml"; \
	tar -C "$$STAGE" --exclude='.git' --exclude="sshcast-relay-$$VER/target" --exclude="sshcast-relay-$$VER/sshcast-proto/target" -czf "$$STAGE/sshcast-relay-$$VER.tar.gz" "sshcast-relay-$$VER"; \
	cp "$$SPEC" "$$STAGE/"; \
	rpmbuild -bs \
		--define "_topdir $$STAGE/rpmbuild" \
		--define "_sourcedir $$STAGE" \
		--define "_specdir $$STAGE" \
		--define "_srcrpmdir $$OUTDIR" \
		"$$STAGE/$$(basename "$$SPEC")"
