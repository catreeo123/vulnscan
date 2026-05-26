---
type: AFK
triage: ready
origin: F13 (extra-high-recall code-review, PLAUSIBLE — noise on cross-user re-open)
---

# Conditional `chmodSync`: skip when perms already correct

## Parent

Post-Group-1 code-review.

## What to build

`openDb` in `local-db.ts` calls `chmodSync(path, 0o600)` unconditionally on every invocation. If the DB file already has mode `0o600` (the common case after the first run), the call is a no-op but still costs a syscall. If the file is owned by a different uid (e.g. a prior run executed under `sudo` in CI), the call fails with `EPERM`, gets caught, and emits a stderr warning on **every** subsequent invocation — potentially tripping CI stderr-non-empty failure detectors.

End-to-end behavior: stat the file before chmod; skip the chmod if `(mode & 0o777) === 0o600`. If the stat itself fails (file just created by `new Database` so stat must succeed, but be defensive), proceed with the chmod attempt as today.

## Acceptance criteria

- [ ] `openDb` runs `statSync(path)` and only attempts `chmodSync` when current perms differ from `0o600`.
- [ ] A test seeds a DB file with `0o600` already set, opens it, and asserts no stderr warning is emitted (verifies the chmod was skipped).
- [ ] A test seeds a DB file owned by the current user with `0o644`, opens it, and asserts perms become `0o600`.
- [ ] Windows skip remains intact for both new tests.

## Blocked by

- None — can start immediately.
