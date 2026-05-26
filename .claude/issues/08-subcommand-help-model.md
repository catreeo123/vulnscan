---
type: HITL
triage: design-needed
origin: F6 (extra-high-recall code-review, PLAUSIBLE — UX surprise)
---

# Scope `-h` / `--help` to subcommands

## Parent

Post-Group-1 code-review.

## What to build

`parseArgs` short-circuits on `argv.includes('--help' | '-h')` BEFORE any positional parsing. Result: `vulnscan check pkg@1.0.0 -h` returns global help instead of check-specific help (or instead of failing with a missing-target message).

Two design options to decide between:

- (a) **Subcommand-aware help.** Move the help detection AFTER positional parsing. When `-h`/`--help` is paired with a command, return `{ command: 'help', topic: 'scan' | 'check' | 'update' }` and render a subcommand-specific usage section. More code, better UX.
- (b) **Global-only help, document it.** Keep current behavior; update the help text to say "`-h` shows this help; for command-specific guidance, see the README." Minimal change.

Decision affects the public CLI contract.

## Acceptance criteria

- [ ] An ADR captures the chosen model.
- [ ] If (a): three subcommand-specific usage sections render correctly; tests cover each.
- [ ] If (b): help text mentions the limitation; no test changes required beyond the existing N1 coverage.
- [ ] Existing N1 tests for bare `--help` / `-h` still pass.

## Blocked by

- None to implement, but blocked on the **design decision** above.
