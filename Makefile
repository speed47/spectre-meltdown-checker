SHFMT      := shfmt
SHFMT_OPTS := -i 4 -ci -ln bash

OUTPUT     := spectre-meltdown-checker.sh
SRC_FILES  := $(shell find src -name '*.sh' -type f) build.sh

.PHONY: all build shellcheck fmt fmt-check

all: build shellcheck fmt-check

build:
	@./build.sh $(OUTPUT)

shellcheck: $(OUTPUT)
	@echo Running shellcheck...
	@shellcheck $(OUTPUT)

fmt:
	$(SHFMT) -w $(SHFMT_OPTS) $(SRC_FILES)

fmt-check:
	@echo Checking formatting...
	@$(SHFMT) -d $(SHFMT_OPTS) $(SRC_FILES)
