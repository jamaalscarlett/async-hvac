SHELL := /bin/bash
UV ?= uv
CODEX_PYTHON ?= 3.10
CODEX_VAULT_VERSION := 1.21.0
CODEX_VAULT_BINARY := /tmp/async-hvac/vault_$(CODEX_VAULT_VERSION)

test: download_vault
	tox

test-codex:
	@log=$$(mktemp) || exit 1; \
	trap 'rm -f "$$log"' EXIT; \
	( if [[ ! -x "$(CODEX_VAULT_BINARY)" ]]; then \
		./download_vault.sh "$(CODEX_VAULT_VERSION)" || exit $$?; \
	fi; \
	VAULT_BINARY="$(CODEX_VAULT_BINARY)" $(UV) --quiet run --no-project \
		--python "$(CODEX_PYTHON)" --with-requirements requirements-dev.txt \
		python -m pytest -qq --tb=line async_hvac/tests; \
	) >"$$log" 2>&1 || { status=$$?; cat "$$log"; exit $$status; }

download_vault:
	if [[ ! -f "/tmp/async-hvac/vault_1.18.5" || \
	      ! -f "/tmp/async-hvac/vault_1.19.5" || \
	      ! -f "/tmp/async-hvac/vault_1.20.4" || \
		  ! -f "/tmp/async-hvac/vault_1.21.0" ]]; then \
		./download_vault.sh; \
	fi

clean:
	rm -rf dist async_hvac.egg-info

distclean: clean
	rm -rf build async_hvac/version .tox

package:
	$(UV) build

.PHONY: clean distclean download_vault package test test-codex
