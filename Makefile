include standard.mk

CHECK_EXTRA := modverify legacyarch delivery

.PHONY: modverify legacyarch delivery
modverify:
	$(GO) mod verify
legacyarch:
	python3 scripts/check-architecture.py
	python3 scripts/test_architecture.py
delivery:
	python3 scripts/check-delivery.py
