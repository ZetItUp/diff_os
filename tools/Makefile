# Compiler
CC = gcc
CFLAGS = -O2 -Wall -Wextra -Wno-format-truncation

# Paths
BUILD_DIR = ../build

# Source
SRCS := $(wildcard *.c)
TOOLS := $(SRCS:.c=)
TARGETS := $(addprefix $(BUILD_DIR)/, $(TOOLS))

all: $(TARGETS)

$(BUILD_DIR)/%: %.c | $(BUILD_DIR)
	@echo "[CC] Compiling $<"
	@$(CC) $(CFLAGS) $< -o $@

$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

clean:
	@rm -f $(TARGETS)

.PHONY: all clean

