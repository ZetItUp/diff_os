# Repository Guidelines

## Project Structure & Module Organization
Core boot code lives in `boot/`, with the freestanding kernel split across `kernel/` and `kernel/includes/`. Loadable drivers and their build scripts sit under `drivers/`, while userland examples are in `programs/` and tooling support resides in `DiffC/`, `tools/`, and `games/`. Generated artifacts land in `build/`, disk images in `image/`, and runtime logs such as `serial.log` or `debugcon.log` stay at the repo root for quick inspection.

## Build, Test, and Development Commands
- `make all` builds the bootloader, kernel, drivers, and supporting tools in one pass.
- `make run` launches the latest build in QEMU; pair with `serial.log` to verify boot output.
- `make DEBUG=1 run` enables symbol-rich binaries and `DIFF_DEBUG` logging for instrumentation work.
- `make diffc`, `make progs`, and `make -C drivers/` rebuild the DiffC utilities, user programs, or driver tree respectively.
- `make clean && make run` mirrors the README’s cold-build path when toolchain configuration changes.

## Coding Style & Naming Conventions
Use GNU99 C for freestanding code, include `<stdint.h>` or `<stdbool.h>` explicitly, and favor fixed-width integers. Indent with 4 spaces, brace in K&R style, keep functions and variables in `snake_case`, and reserve `UPPER_SNAKE_CASE` for macros. When mapping hardware registers, document bit layouts alongside the code. Avoid host libc calls; reuse helpers already present in DiffC or the kernel.

## Testing & Debugging Guidelines
There is no automated harness—validate changes by running `make run` or `make DEBUG=1 run` and reviewing `serial.log`/`debugcon.log`. For regressions, add focused programs in `programs/` or lightweight DiffC utilities, then share repro steps. Keep temporary tracing behind `#ifdef DIFF_DEBUG` so release builds stay quiet.

## Commit & Pull Request Guidelines
Commits in this repository are concise and action-oriented (`Updated dterm`, `Memory issues fixes`); follow suit with short, present-tense summaries and logical change grouping. PRs should describe the subsystem touched, note impacts on boot flow or loaders, link related issues, and attach QEMU or log excerpts when behavior shifts. Call out follow-up tasks or tooling requirements so the next agent can continue confidently.
