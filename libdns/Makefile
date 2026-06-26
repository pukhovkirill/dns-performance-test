# /libdns/Makefile
# Target names for the static library and the test executable
TARGET_LIB := libdns.a
TEST_EXEC  := libdns_run_tests

# Directory definitions
BUILD_DIR := ../build/libdns
SRC_DIRS  := src
INC_DIRS  := include
TEST_DIRS := tests
COV_DIR   := $(BUILD_DIR)/coverage_reports

# Include-What-You-Use settings
IWYU       := include-what-you-use
IWYUFLAGS  :=

# Archiver settings for creating the static library
AR      := ar
ARFLAGS := rcs

# Locate all source files without redundant relative dots in paths
SRCS      := $(wildcard $(SRC_DIRS)/*.c)
TEST_SRCS := $(wildcard $(TEST_DIRS)/*.c)

# Explicitly map object files to separate folders inside the build directory
OBJS      := $(patsubst $(SRC_DIRS)/%.c, $(BUILD_DIR)/src/%.o, $(SRCS))
TEST_OBJS := $(patsubst $(TEST_DIRS)/%.c, $(BUILD_DIR)/tests/%.o, $(TEST_SRCS))

# Generate dependency files (.d) for automatic tracking of header changes
DEPS      := $(OBJS:.o=.d) $(TEST_OBJS:.o=.d)

# Compiler flags (-Iinclude tells both gcc and CLion where to find headers)
INC_FLAGS := -I$(INC_DIRS)
CPPFLAGS  := $(INC_FLAGS) -MMD -MP
CFLAGS    := -Wall -Wextra -O2 -std=c99

ifdef COVERAGE_ENABLE
  CFLAGS := -Wall -Wextra -O0 -std=c99 --coverage
  LDFLAGS += --coverage
endif

# The default target MUST include both the library and tests so CLion indexes all files
.PHONY: all
all: $(BUILD_DIR)/$(TARGET_LIB) $(TEST_OBJS)

# Rule to archive object files into a static library (.a)
$(BUILD_DIR)/$(TARGET_LIB): $(OBJS)
	@mkdir -p $(dir $@)
	$(AR) $(ARFLAGS) $@ $(OBJS)

# Rule to link the test executable against the newly built static library
$(BUILD_DIR)/$(TEST_EXEC): $(TEST_OBJS) $(BUILD_DIR)/$(TARGET_LIB)
	@mkdir -p $(dir $@)
	$(CC) $(TEST_OBJS) -L$(BUILD_DIR) -ldns $(LDFLAGS) -o $@

# Pattern rule to compile source files from the src directory
$(BUILD_DIR)/src/%.o: $(SRC_DIRS)/%.c
	@mkdir -p $(dir $@)
	-$(IWYU) $(IWYUFLAGS) $(CPPFLAGS) $(CFLAGS) $< 2>&1
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

# Pattern rule to compile test files from the tests directory
$(BUILD_DIR)/tests/%.o: $(TEST_DIRS)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

# Target to execute the test suite (triggered from the root Makefile)
.PHONY: test
test: $(BUILD_DIR)/$(TEST_EXEC)
	@$(BUILD_DIR)/$(TEST_EXEC)

# Target to generate the gcov reports
.PHONY: coverage
coverage:
	@$(MAKE) clean
	@$(MAKE) test COVERAGE_ENABLE=1
	@echo "--- Generating gcov reports for libdns ---"
	mkdir -p $(COV_DIR)
	lcov --capture --directory $(BUILD_DIR) --output-file $(COV_DIR)/coverage.info
	genhtml $(COV_DIR)/coverage.info --output-directory $(COV_DIR)/html
	@echo "Coverage reports ready in $(COV_DIR)/html/index.html"

# Target to clean up all build artifacts for this module
.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)

# Include the generated dependency files (ignores them if they don't exist yet)
-include $(DEPS)
