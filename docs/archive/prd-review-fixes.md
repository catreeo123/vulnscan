# PRD: Correctness & hardening fixes from whole-repo review (8 bugs)

> Source: extra-high-effort whole-repo code review (`/code-review` → `/scrutinize`). Each
> item below was verified against source **and** its co-located test before inclusion.
> Report-only/nit findings are listed under **Out of Scope**.

## Problem Statement

A maintainer relies on `vulnscan` both as a local scanner and as the producer of the
shared `db-latest` advisory database that every other install bootstraps from. A
whole-repo review surfaced eight defects that let the tool **silently report clean when
it should not**, **publish a degraded database**, or **brick its own install** — exactly
the failures a security tool must never have. None are caught by the current test suite
because they live on untested surfaces (CI exit paths, network/error paths, arg edge
cases, first-run download).

## Solution

Fix all eight, each with a red→green regression test, so the tool fails *safe* (loud,
non-zero, last-good-data-preserved) instead of failing *silent*. Where a defect is caused
by duplicated logic, fix it at depth: extract the duplicated rule into a single tested
seam rather than patching the copy.

## User Stories

1. As a CI maintainer, I want `vulnscan update` to exit non-zero when the GitHub Advisory
   sync is incomplete, so that a partial sync never overwrites the good `db-latest` asset.
2. As a downstream consumer of `db-latest`, I want a failed nightly refresh to keep the
   last-good database, so that I never bootstrap from a database missing advisory data.
3. As a security engineer, I want a package flagged as malware by **either** OSV or the
   GitHub Advisory malware feed to always be `critical`, so that `--fail-on critical`
   never misses a known-malicious package.
4. As a first-run user on a flaky network, I want an interrupted bootstrap download to
   leave no database behind, so that the next run retries cleanly instead of crashing on
   a corrupt file forever.
5. As a CLI user, I want `--fail-on=critical` (equals form) to be honored exactly like
   `--fail-on critical`, so that my chosen fail threshold is never silently dropped.
6. As a CLI user, I want `--fail-on=low` to actually lower the gate, so that a `moderate`
   finding causes exit 1 instead of being silently swallowed by the default threshold.
7. As a CLI user, I want `vulnscan check @scope/pkg` with no version to print a usage
   error, so that I am not told a package is clean when nothing was actually checked.
8. As a project owner, I want a malformed `.vulnscanrc` to produce a warning, so that a
   typo in my config does not silently revert me to the default fail threshold.
9. As a developer importing or tooling around `cli.ts`, I want importing the module to
   have no side effects, so that it does not open the database, hit the network, or set
   `process.exitCode` merely on import.
10. As a repository owner, I want the release workflow to be immune to tag-name shell
    injection, so that a crafted tag cannot execute arbitrary commands with the
    `contents: write` token.
11. As a maintainer reading the code, I want the `mal → critical` rule to exist in exactly
    one place, so that the OSV and GitHub Advisory sync paths can never drift apart again.
12. As a maintainer, I want every fix covered by a behavior-level test, so that these
    regressions cannot silently reappear.
13. As an operator, I want a GitHub-Advisory outage to fail the whole nightly refresh
    loudly (keeping last-good `db-latest`) rather than silently publishing OSV-only data.

## Implementation Decisions

**Deep module extraction (chosen by maintainer):**
- Extract a single severity-resolution seam in `severity-mapper.ts`:
  `resolveAdvisorySeverity(type, label, advisoryId)` that wraps the existing
  `mapSeverity` and applies the malware override. Both `osv-sync` and
  `github-advisory-sync` call it. This removes the duplicated `type === 'mal' ? 'critical'`
  rule (currently only in `osv-sync`) — the duplication is the root cause of the malware
  false-negative.
  ```
  resolveAdvisorySeverity(type, label, id):
    const { severity, warning } = mapSeverity({ label, advisoryId: id })
    return { severity: type === 'mal' ? 'critical' : severity, warning }
  ```

**Sync / exit-code contract:**
- `runSync` changes return type from `void` to `ScanWarning[]` (collected via push-loops,
  not spread — preserve the issue-#24 stack-safety guarantee). It keeps writing GitHub
  warnings to stderr for visibility.
- The `update` command computes `hasIncomplete(warnings) ? 2 : 0`, matching the documented
  exit-code matrix already used by `scan`/`check`. OSV failures already throw → exit 1; the
  gap was GitHub failures (caught → `incomplete` warning → previously swallowed).
- **Accepted tradeoff:** a GitHub-Advisory-only outage now causes the CI `update` step to
  exit non-zero, so the nightly publish is skipped and the last-good `db-latest` is kept.
  This is fail-safe but delays OSV freshness during a GitHub outage. The CI workflows rely
  on GitHub Actions' default `bash -e`: a non-zero `update` fails the step and skips the
  gzip/upload steps. No `continue-on-error` is added.

**First-run bootstrap atomicity:**
- `bootstrap.ts` downloads to a sibling temp path (`DB_PATH + ".download-" + pid`), then
  `renameSync` to `DB_PATH` only on full success (atomic publish on the same filesystem).
  On any failure the temp file is removed and the error rethrown to the existing
  fallback-to-sync handler. This also removes the concurrent-bootstrap corruption window
  (each process writes its own temp, last atomic rename wins with a complete file).

**Arg parsing:**
- `cli-args.ts` accepts `--flag=value` for all value-flags (`--format`, `--fail-on`,
  `--dir`) by splitting on the first `=` only when the token starts with `--`. Space form,
  boolean flags, orphan-flag warnings, and `@`-bearing positionals are unaffected.

**check command:**
- `cli.ts` `check` guards on `lastIndexOf('@') <= 0` (covers both no-`@` and
  leading-`@` scoped-without-version) and prints the existing usage error.

**Config robustness:**
- `config.ts` distinguishes a missing file (`ENOENT` → silent, try next location) from a
  malformed/unreadable file (warn to stderr, then continue). Behavior on a genuinely
  absent config is unchanged.

**Module side-effect hygiene:**
- `cli.ts` guards the module-scope `run(...)` invocation behind a realpath-based "is this
  the entry point" check, so importing the module no longer dispatches a command. The bin
  entry (`node dist/cli.js`) and the e2e harness (`tsx src/cli.ts`) still execute normally.

**CI hardening:**
- `release.yml` passes `github.ref_name` via an `env:` variable and references it quoted
  in the `run:` script, eliminating expression injection.

## Testing Decisions

A good test asserts **external behavior**, not implementation details: given inputs/state,
the observable output (return value, stderr text, exit code, store calls, file operations
via mocks) is correct. Prior art in the repo: `sync-orchestrator.test.ts` (mocks
`osv-sync`/`github-advisory-sync`, asserts returned `ScanWarning[]` and stderr),
`bootstrap.test.ts` (mocks `node:fs`/`node:zlib`/`node:stream/promises`),
`github-advisory-sync.test.ts` (stubs `fetch`, asserts `store.upsert` calls and
`type`/severity), `config.test.ts` (writes a temp `.vulnscanrc`, asserts stderr warnings),
`cli-args.test.ts` (pure parse assertions), `cli.test.ts` (`computeExitCode` table).

Modules to test (maintainer chose: all in-scope fixes):
- `severity-mapper` — `resolveAdvisorySeverity`: `mal → critical` regardless of label;
  `cve` passes severity through; missing-label warning preserved.
- `github-advisory-sync` — a `type=malware` advisory with a non-critical GitHub severity is
  stored `critical`.
- `cli-args` — `--fail-on=critical`, `--format=json`, `--dir=/x` parse identically to the
  space form; space form and orphan-flag warnings still pass.
- `config` — malformed JSON `.vulnscanrc` warns to stderr and falls back; absent file stays
  silent.
- `cli` — `check @scope/pkg` (no version) returns the usage error / exit 1.
- `sync-orchestrator` — `runSync` returns the GitHub `incomplete` warning when the GitHub
  sync reports one (proxy for the un-unit-testable `update` exit wiring).
- `bootstrap` — success path calls `renameSync(tmp, DB_PATH)`; a `pipeline` rejection
  removes the temp file and does **not** rename (mock `renameSync`/`rmSync`).

Not unit-tested (verified by e2e + manual): the `update` step's exit→CI-skip behavior
(e2e only exercises `update --help`), the `release.yml` change (YAML, no test harness).

## Out of Scope

Report-only / refuted findings from the review (nits, no production trigger, or documented
contracts), not addressed here:
- `secrets.ts` Bearer regex excludes base64 `+/=` — real tokens in this app are
  `ghp_`/`github_pat_`, already covered by dedicated patterns.
- `affected-range-matcher` silent miss on non-semver `dep.version` / whitespace-only
  `rawRange` — npm lockfile versions are always valid semver; GitHub never emits a blank
  range.
- `InMemoryAdvisoryStore` prune/ordering divergence from `SqliteAdvisoryStore` — test
  double only, no production path.
- JSON output drops warning `class` / omits `fix` when absent — documented `string[]` /
  `string | undefined` contract; changing it is a schema change.
- `retry-after` HTTP-date → `NaN` backoff, unbounded GitHub per-item warnings — nits.
- `file:`-dep alias misclassification — narrow multi-condition, low/unverified.
- ancestry empty when `package.json` absent — `via` enrichment only, no missed finding.
- `--fail-on MODERATE` case rejection — lowercase is the tested contract; a warning fires.

No changes to the JSON output schema, the exit-code matrix semantics, the AdvisoryStore
interface, or the deterministic ordering guarantees.

## Further Notes

- Per `CLAUDE.md`: these are bug fixes → **patch** version bump in `package.json` plus a
  matching `CHANGELOG.md` entry when shipped.
- `runSync`'s stale comment ("no since filter") will be corrected while that file is open —
  GitHub sync is intentionally incremental even under `update` (warm-start + incremental is
  the CI refresh design).
- Implementation order suggestion (independent slices): severity resolver (#2/#11) →
  sync/exit (#1/#13) → bootstrap (#4) → cli-args (#5/#6) → check guard (#7) → config (#8) →
  isMain (#9) → release.yml (#10).
