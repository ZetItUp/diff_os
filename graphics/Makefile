# Graphics Makefile
# Automatically copies all files and directories to image/system/graphics
# Excludes: source/ (contains source files like .aseprite) and Makefile

DEST = ../image/system/graphics

# Find all items except source and Makefile
ITEMS := $(filter-out source Makefile,$(wildcard *))

.PHONY: all clean

all:
	@echo "[GRAPHICS] Copying graphics files..."
	@mkdir -p $(DEST)
	@for item in $(ITEMS); do \
		cp -r "$$item" $(DEST)/; \
		echo "[GRAPHICS] Copied $$item"; \
	done
	@echo "[GRAPHICS] Done"

clean:
	@echo "[GRAPHICS] Cleaning destination..."
	@rm -rf $(DEST)
