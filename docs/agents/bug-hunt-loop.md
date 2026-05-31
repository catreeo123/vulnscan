# Bug-Hunt Convergence Loop — Experience & Playbook

Operational guidance for running a multi-pass, two-gate correctness bug-hunt over this repo
(or any security-sensitive scanner). Written from a 9-pass session that fixed 16 bugs and
reached convergence (`v0.2.18 → v0.2.22`). Read this before starting a similar loop — it will
save you several passes' worth of mistakes.

## The loop in one paragraph

Each pass = (a) a self-directed multi-lens hunt over `src/` + (b) 2–3 **freshly spawned,
un-primed** independent reviewers (sonnet) given ONLY the source and "find correctness bugs"
— no hint about what was checked or believed-clean. Every candidate is adversarially verified
(trace the real code path; empirically check "never/always happens" claims). Confirmed
blocker/major bugs are fixed via TDD (red reproducing test → green). A pass is **clean** only
when BOTH gates report zero confirmed blocker/major AND no code changed. Convergence = **two
consecutive clean passes**. Any confirmed-and-fixed bug resets the count to 0.

---

## 1. What worked

- **Un-primed independent reviewers are the load-bearing gate.** Self-review converges to
  "looks clean" and then rationalizes away real bugs. The un-primed reviewers caught defects
  the self-hunt had dismissed. Do not anchor them — telling a reviewer "we think this is clean"
  or "we already checked X" reproduces your own blind spots in theirs.
- **Rotate reviewer framings every pass.** Used: sync+db / scan-pipeline / holistic →
  sev-type-dedup / scan / holistic → error-paths / semver / holistic → concurrency / data-
  integrity / holistic → output+CLI / adversarial-input / holistic → false-negative-red-team /
  data-flow / holistic. Different lenses surface disjoint bug classes; identical framings
  re-find the same things.
- **Empirical refutation beats assertion.** Two "MAJOR" reviewer claims were killed by data,
  not argument: scanning the entire OSV npm corpus (~220k advisories) showed `limit` events in
  **0** ranges and CVSS `severity[]`-without-string-label in **0** entries. A live GitHub API
  sample (0/200 null ranges) killed another. When a finding hinges on "upstream produces X,"
  measure X.
- **Internal-asymmetry detection finds real bugs fast.** The Pass-6 MAJOR (`runSync` OSV
  failure → exit 1) was provable because the *same function* degraded a GitHub failure to exit
  2 but an OSV failure to exit 1. Same failure class, two exit codes = bug.
- **TDD per fix, full proof per pass.** Every fix got a co-located red→green test; every pass
  ended with `npm test` (state the count) + `npm run build` (0 tsc errors) + `graphify update`.
- **A written "permanent defer set."** Maintaining an explicit list of refuted/deferred minors
  *with the evidence for each* stopped the loop from re-litigating them every pass.

## 2. What went wrong (and the lesson each time)

- **Self-review rationalized away a real MAJOR.** In Pass 5 the `runSync` exit-code issue was
  downgraded to "minor — CI `set -e` treats exit 1 and 2 the same." Three independent reviewers
  across two passes kept flagging it; only then was the decisive evidence (the OSV-vs-GitHub
  exit-code asymmetry) found and the bug confirmed. **Lesson:** when ≥2 independent reviewers
  flag the same thing across passes, distrust your dismissal and go find the *decisive*
  evidence — do not re-state the dismissal.
- **Convergence-counting was conflated.** Early on, "zero confirmed blocker/major" got muddled
  with "any confirmed bug resets." **Lesson:** classify every candidate into exactly one of
  three buckets — (i) confirmed blocker/major → fix via TDD, resets count; (ii) confirmed minor
  worth fixing → fix, resets count (code changed); (iii) refuted / non-reachable / breaking-
  schema / by-design → document, does NOT reset. A pass is clean only with zero (i)+(ii) AND no
  code changed.
- **A reviewer gate was aborted by rate-limiting and nearly counted as clean.** All three Pass-4
  reviewers returned only "session limit" errors. **Lesson:** an empty/aborted reviewer is not
  a zero-bug reviewer. Re-spawn after the limit resets; never score a gate on missing output.
  (Reviewers also occasionally returned a truncated progress line instead of findings — re-spawn
  those too.)
- **The recurring-minor trap.** A finite set of minors (JSON warning-`class` strip, ancestry
  `via` display, double `loadConfig`, etc.) gets re-surfaced *every* pass. Fixing minors forever
  resets the count forever → you never converge. **Lesson:** decide each minor ONCE (fix-now or
  defer-with-reason), record it in the permanent-defer set, and don't reopen it without new
  evidence.
- **Reviewers anchored on false premises about consumers/upstream.** "CI reads exit 1 as
  findings" was false for this repo (the db-refresh workflow runs `update` as a bare step where
  any non-zero blocks publish). "OSV uses `limit` events for npm" was false (0/220k). **Lesson:**
  verify the *premise* (the consumer's actual behavior, the upstream's actual data), not just
  the code path. A correct code-trace on a wrong premise is a false positive.
- **Consistency-completion minors are worth fixing, but cost a reset.** After guarding `type` in
  the `ON CONFLICT` clause (Pass 5), `canonical_id` was left unguarded and got re-flagged
  (Pass 7). **Lesson:** when you touch a clause/pattern, fix the whole class at once so it
  cannot recur — partial fixes guarantee a future-pass reset.

## 3. Playbook for the next session

**Per pass**
1. Self-hunt `src/`, rotating the lens (concurrency/WAL, semver boundaries, error/exit paths,
   data-integrity prune/dedup/PK-collision, malformed input, output/render, false-negative
   red-team). Probe highest-blast modules hardest: `sync-orchestrator`, `osv-sync`,
   `github-advisory-sync`, `local-db`, `lockfile-resolver`, `affected-range-matcher`.
2. Spawn 2–3 fresh sonnet reviewers, each a DIFFERENT framing, each un-primed (source +
   "find correctness bugs" only; exclude external-DB-tampering and MITM as out-of-scope so they
   focus on realistic inputs). Run them in parallel.
3. Adversarially verify every candidate: trace the real path; for "never/always happens" claims
   download/scan the real corpus or hit the live API in a sandbox.
4. Bucket each candidate (i/ii/iii above). Fix (i) and (ii) via TDD. Document (iii) in the defer
   set with evidence.
5. Bump `package.json` + CHANGELOG per fix; `npm test` (state count) + `npm run build` +
   `graphify update .`.
6. Surface the verdict: pass #, self-hunt confirmed, reviewer confirmed, total fixed, clean-count.

**Domain bug-taxonomy (the false-negative classes that actually occur here)**
- Warning misclassification: `informational` (exit 0/1) vs `incomplete` (exit 2). Rule:
  `incomplete` ⟺ detection coverage is reduced. A degraded *display* (ancestry) is informational;
  a never-synced source or an uncheckable version is incomplete.
- Cross-source PK collision `(id, package_name)`: an OSV full-sync must not overwrite a
  `source='github'` row's curated `type` / `severity` / `affected_ranges_json` / `canonical_id`.
  Every curated column needs the `CASE WHEN advisories.source = 'github'` guard.
- Empty/missing version → `semver.satisfies('', range)` is always false → silent false-clean.
  Surface as `incomplete`, never a `0.0.0`/`''` dep.
- Malware classification must derive from `MAL-` in `entry.id`/aliases — NOT from the display id
  (`getBestId` prefers a CVE alias), or the `mal → critical` override is bypassed.
- Error-path exit-code symmetry: every external-sync failure (OSV and GitHub) must degrade to
  `incomplete` (exit 2), not throw to the top-level catch (exit 1). Local-invariant failures
  (prune/cursor) intentionally propagate.
- Semver matching: `semver.satisfies` silently returns false for an invalid range string — the
  classic false-negative mechanism. Empty `introduced` must use `|| '0'`, not `?? '0'`.

**Permanent defer set (verified non-blocking — do NOT re-fix without new evidence)**
- `renderJson` strips warning `class` → breaking JSON-schema change; exit code already encodes
  incomplete via `computeExitCode` before render.
- GitHub cursor set at sync-end → ms race window, OSV provides overlapping coverage.
- `firstFixed` omits `<=` / `v`-prefixed fix versions in JSON → display-only remediation hint.
- `--fail-on` case-sensitivity → fail-safe (widens to defaults) and warns to stderr.
- `mapRowsSafely` silent drop / lockfile `resolved`-without-`version` / empty `ghsa_id` →
  non-reachable from npm-produced lockfiles or the tool's own validated writes (would need DB
  tampering or MITM).
- `eventsToRanges` ignores `limit` / `osv-sync` ignores CVSS `severity[]` → empirically
  non-reachable (0/220k npm advisories; CVSS always co-occurs with a string label). See the
  `osv-npm-severity-data-shape` memory.

**Tooling gotchas**
- `ctx_execute` runs Bun: it cannot load `better-sqlite3` (`ERR_DLOPEN_FAILED`) and rejects ESM
  `import` — use `require(...)` + an async IIFE, with absolute module paths. For SQLite
  verification use Node via Bash.
- The context-mode hook redirects inline `fetch`/`curl` — do network work inside `ctx_execute`
  and `console.log` only the derived summary.
- `unset GITHUB_TOKEN` before any `gh` call (the env token has empty scopes).
- `.claude/worktrees/` stale git worktrees get globbed as phantom duplicate test suites — the
  `vitest.config.ts` exclude handles this; don't let a re-add reintroduce it.
- Don't fix the same minor twice: check this doc's defer set first.
