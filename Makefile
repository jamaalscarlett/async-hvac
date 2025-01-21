SHELL := /bin/bash

test: version download_vault
	tox

download_vault:
	if [[ ! -f "/tmp/async-hvac/vault_1.16.3" || \
	      ! -f "/tmp/async-hvac/vault_1.17.6" || \
	      ! -f "/tmp/async-hvac/vault_1.18.3" ]]; then \
		./download_vault.sh; \
	fi

clean:
	rm -rf dist async_hvac.egg-info

distclean: clean
	rm -rf build async_hvac/version .tox

package:
	python setup.py sdist

.PHONY: clean package publish test version
