PHANTOM_SSH_USER := phantom
PHANTOM_SSH_HOST_PORT := 2222
PHANTOM_SSH_HOST := localhost
PHANTOM_APP_ROOT := /home/$(PHANTOM_SSH_USER)/apps
PHANTOM_APP_WORKSPACE := phHTTP_Cats


.PHONY: help
help:
	@echo "Usage: make [options]"
	@echo "Options:"
	@echo "help			- this help"
	@echo "prepare			- decompile Phantom packages for IDE code completion (in Phantom server)"
	@echo "upload			- upload application to Phantom server from local workstation"


/opt/phantom/usr/python36/lib/python3.6/site-packages/uncompyle6/__init__.py:
	@/opt/phantom/usr/bin/python -m pip install uncompyle6

.PHONY: prepare
prepare: /opt/phantom/usr/python36/lib/python3.6/site-packages/uncompyle6/__init__.py
	@mkdir -p ~/.phantom-packages
	@libs=( /opt/phantom/lib3/ /opt/phantom/pycommon3/ );\
	for lib_path in "$${libs[@]}"; do cd $$lib_path; \
		for file in $$(find . -name "*.pyc"); do uncompyle6 -o ~/.phantom-packages/$${file::-1} $$file; done; \
	done

.PHONY: upload
upload:
	@ssh -p $(PHANTOM_SSH_HOST_PORT) $(PHANTOM_SSH_USER)@$(PHANTOM_SSH_HOST) mkdir -p $(PHANTOM_APP_ROOT)/$(PHANTOM_APP_WORKSPACE)/$(PHANTOM_APP_NAME)/
	@rsync -av -e 'ssh -p $(PHANTOM_SSH_HOST_PORT)' \
		--exclude '.venv' \
		--exclude '.mypy_cache' \
			./. $(PHANTOM_SSH_USER)@$(PHANTOM_SSH_HOST):$(PHANTOM_APP_ROOT)/$(PHANTOM_APP_WORKSPACE)/$(PHANTOM_APP_NAME)/
