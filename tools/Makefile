# Compiler
CC = gcc
CFLAGS = -O2 -Wall -Wextra -Wno-format-truncation

# Paths
BUILD_DIR = ../build

# Source
SRCS := $(wildcard *.c)
TOOLS := $(SRCS:.c=)
TARGETS := $(addprefix $(BUILD_DIR)/, $(TOOLS))
LOCAL_TARGETS := $(TOOLS)

all: $(TARGETS) $(LOCAL_TARGETS)

$(BUILD_DIR)/%: %.c | $(BUILD_DIR)
	@echo "[CC] Compiling $<"
	@$(CC) $(CFLAGS) $< -o $@

%: $(BUILD_DIR)/%
	@cp $< $@

$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

clean:
	@rm -f $(TARGETS) $(LOCAL_TARGETS)

.PHONY: all clean
