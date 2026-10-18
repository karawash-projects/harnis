# Convenience wrapper for people who have make. Everything is implemented in
# tasks.py, which works the same on Windows, macOS and Linux:
#     python tasks.py --help
PY ?= python3

TASKS := install env up up-full down sandbox-image dev migrate token test redteam maintenance clean

.PHONY: $(TASKS) test-unit test-integration test-sandbox help
$(TASKS):
	$(PY) tasks.py $@

test-unit:
	$(PY) tasks.py test unit
test-integration:
	$(PY) tasks.py test integration
test-sandbox:
	$(PY) tasks.py test sandbox
help:
	$(PY) tasks.py --help
