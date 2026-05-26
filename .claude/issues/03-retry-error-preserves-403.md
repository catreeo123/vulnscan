---
type: AFK
triage: ready
origin: F4 (extra-high-recall code-review, PLAUSIBLE)
---

# Preserve 403 status in `fetchWithRetry` final-attempt error

## Parent

Post-Group-1 code-review (commit `e859d2f` review pass).

## What to build

`fetchWithRetry` in `github-advisory-sync.ts` currently masks the final-attempt 403 (expired/invalid `GITHUB_TOKEN`) as the generic `GitHub API: max retries exceeded`. A user sees no signal that the failure was auth-related.

End-to-end behavior: on the final retry attempt, when the response is 401/403, throw a status-carrying error like:

```
GitHub API error: 401 Unauthorized — check GITHUB_TOKEN
```

Rate-limit-only failures (429 on the final attempt) keep the existing `max retries exceeded` shape, since 429 is a transient bound — auth failures are not.

## Acceptance criteria

- [ ] Final-attempt 401 throws an error whose message contains `401`.
- [ ] Final-attempt 403 throws an error whose message contains `403`.
- [ ] Final-attempt 429 keeps the existing `max retries exceeded` shape.
- [ ] Unit test mocks a fetch returning 403 on every attempt and asserts the thrown error message includes `403`.

## Blocked by

- None — can start immediately.
