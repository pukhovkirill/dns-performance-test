# /Makefile
# Enumerate subdirectories containing their own Makefiles
MODULES := libdns

# Declare phony targets to prevent conflicts with files of the same name
.PHONY: all clean test $(MODULES)

# Default target: Builds all specified modules sequentially
all: $(MODULES)

# Rule for building a specific module by switching to its directory
$(MODULES):
	$(MAKE) -C $@

# Pattern rule to run tests for a specific module
%_test:
	$(MAKE) -C $* test

# Target to clean up build artifacts across all subdirectories
clean:
	for dir in $(MODULES); do \
		$(MAKE) -C $$dir clean; \
	done

# Target to run ALL tests across all subdirectories sequentially
test:
	for dir in $(MODULES); do \
		$(MAKE) -C $$dir test; \
	done
