# OS Programming Agent

## Mission
- Focus on kernel, drivers, and low-level tooling tasks in the DiffOS codebase.
- Deliver small, verifiable iterations that keep the tree buildable.
- Document notable design choices or invariants that future contributors need to know.

## Workflow
1. Clarify the feature or bug scenario; gather context from `README.md`, existing code, and commit history.
2. Locate relevant sources with `rg`, preferring headers in `kernel/includes/` to understand available APIs.
3. Propose a minimal change set; split work if it spans kernel, drivers, and userspace programs.
4. Implement with freestanding assumptions (no libc); reuse helpers from DiffC where possible.
5. Build early with `make` targets (see Tooling) to ensure cross-compilation succeeds.
6. Validate behaviour in QEMU when feasible and capture repro steps or logs.
7. Summarize modifications, affected subsystems, and required follow-up tests.

## Tooling
- `make all` for full kernels, drivers, and tools; run before handing off multi-component changes.
- `make run` to boot the OS under QEMU; capture serial or VGA output for debugging.
- `make DEBUG=1 run` for symbol-rich runs; enables `DIFF_DEBUG` logging when instrumentation is present.
- `make debug` to launch the GDB stub (`i386-elf-gdb`) against QEMU.
- `make diffc`, `make progs`, `make -C drivers/`, `make -C tools/`, `make -C games/` for focused builds.
- Prefer `rg`/`rg --files` for navigation; avoid tooling that expects a host libc.

## Coding Standards
- Stick to GNU99 C with freestanding constraints; include `<stdint.h>` and `<stdbool.h>` as needed.
- Functions, variables, and static symbols use `snake_case`; macros stay in `UPPER_SNAKE_CASE`.
- Types rely on fixed-width integers (`uint32_t`, `int32_t`, etc.).
- 4-space indentation, K&R braces, and concise, purposeful comments near complex hardware interactions.
- Guard shared headers with `#ifndef`/`#define`/`#endif`.

## Defensive Practices
- Validate pointers and sizes before dereferencing; return error codes for recoverable faults.
- Avoid dynamic allocation unless the kernel allocator is explicitly safe in the call path.
- Keep interrupt handlers minimal; defer heavy work to tasklets or worker contexts if available.
- Ensure critical sections mask interrupts or use spinlocks that already exist in the subsystem.
- When touching hardware registers, mirror datasheet bit layouts in comments or enums.

## Testing & Debugging
- Use `make DEBUG=1 run` alongside `serial.log` or `debugcon.log` for trace output.
- Wrap temporary logging in `#ifdef DIFF_DEBUG` to keep retail builds clean.
- For regressions, build a minimal repro program under `programs/` or `DiffC` utilities.
- Capture QEMU screenshots or hexdumps in `debugcon.log` rather than modifying kernel output paths.

## Review & Handoff
- Double-check linker scripts and startup code when modifying memory maps or segments.
- Note ABI or syscall surface changes so userland and DiffC can be updated together.
- If tests or QEMU runs are skipped, state the reason and provide commands for the next person.
