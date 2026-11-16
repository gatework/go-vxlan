# Shared gates use the published standard unless a checkout is supplied explicitly.
include standard.mk

CHECK_EXTRA := project-checks

DIST ?= dist
VERSION := $(shell sed -n 's/^const Version = "\([^"]*\)"$$/\1/p' internal/cli/app.go)
REVISION ?= $(shell git rev-parse HEAD)

.PHONY: project-checks project-quality modverify legacyarch delivery package verify-release package-smoke
project-checks: modverify legacyarch delivery

project-quality:
	$(GO) run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12
	python3 scripts/test-reuse-release.py
	python3 scripts/test-publish-release.py

modverify:
	$(GO) mod verify
legacyarch:
	python3 scripts/check-architecture.py
	python3 scripts/test_architecture.py
delivery:
	python3 scripts/check-delivery.py

package:
	GO="$(GO)" sh scripts/package.sh "$(DIST)"
verify-release:
	sh scripts/verify-release.sh "$(DIST)" "v$(VERSION)" "$(REVISION)"
package-smoke: verify-release
	python3 scripts/package-smoke.py "$(DIST)" "v$(VERSION)"
