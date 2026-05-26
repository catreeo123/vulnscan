---
type: AFK
triage: ready
origin: F16 (extra-high-recall code-review, PLAUSIBLE — undici resource warning)
---

# Consume final-attempt 429 response body before throwing

## Parent

Post-Group-1 code-review.

## What to build

`fetchWithRetry` in `github-advisory-sync.ts` now `break`s on the final-attempt 429 without consuming the response body. Node's native fetch (undici) emits a `ResourceWarning: response body not consumed` log line, and the underlying TCP socket may not return to the connection pool promptly — delaying any subsequent fetch in the same process.

End-to-end behavior: before falling out of the retry loop for the terminal 429/403 case, drain or cancel the body.

```ts
await res.body?.cancel()  // discards the body without buffering
```

`cancel` (rather than reading to completion) avoids buffering a potentially-large error page.

## Acceptance criteria

- [ ] After a terminal 429/403, `res.body.cancel()` is awaited before the throw.
- [ ] No `ResourceWarning` from undici when the test runs (capture stderr in the existing M6 test or add a new assertion).
- [ ] Existing M6 timing test still passes (final-attempt sleep is still skipped).

## Blocked by

- None — can start immediately.
