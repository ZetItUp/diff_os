# Compiler
CC = gcc
CFLAGS = -O2 -Wall -Wextra

# Paths
BUILD_DIR = ../build
TARGET = $(BUILD_DIR)/mkdiffos

# Source
SRC = mkdiff.c

all: $(TARGET)

$(TARGET): $(SRC) | $(BUILD_DIR)
	@echo "[CC] Compiling mkdiffos tool"
	@$(CC) $(CFLAGS) $< -o $@

$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

clean:
	@rm -f $(TARGET)

.PHONY: all clean

