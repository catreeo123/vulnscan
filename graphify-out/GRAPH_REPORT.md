# Graph Report - security-scan-cli  (2026-05-31)

## Corpus Check
- 68 files · ~52,141 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 1298 nodes · 2023 edges · 88 communities (74 shown, 14 thin omitted)
- Extraction: 99% EXTRACTED · 1% INFERRED · 0% AMBIGUOUS · INFERRED: 18 edges (avg confidence: 0.81)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `00f4ff8d`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- [[_COMMUNITY_CLI Entry & Architecture Docs|CLI Entry & Architecture Docs]]
- [[_COMMUNITY_CLI Args & Scan Pipeline|CLI Args & Scan Pipeline]]
- [[_COMMUNITY_Advisory Database Layer|Advisory Database Layer]]
- [[_COMMUNITY_Semver Matching & E2E Tests|Semver Matching & E2E Tests]]
- [[_COMMUNITY_Range Match Logic|Range Match Logic]]
- [[_COMMUNITY_Output Rendering|Output Rendering]]
- [[_COMMUNITY_Lockfile Ancestry|Lockfile Ancestry]]
- [[_COMMUNITY_Architecture Decisions (ADRs)|Architecture Decisions (ADRs)]]
- [[_COMMUNITY_OSV Sync|OSV Sync]]
- [[_COMMUNITY_GitHub Advisory Sync|GitHub Advisory Sync]]
- [[_COMMUNITY_E2E Test Fixtures|E2E Test Fixtures]]
- [[_COMMUNITY_Sync Test Helpers|Sync Test Helpers]]
- [[_COMMUNITY_Ancestry Tests|Ancestry Tests]]
- [[_COMMUNITY_Orchestrator Test Helpers|Orchestrator Test Helpers]]
- [[_COMMUNITY_Arg Parser Core|Arg Parser Core]]
- [[_COMMUNITY_Renderer Module|Renderer Module]]
- [[_COMMUNITY_Config Tests|Config Tests]]
- [[_COMMUNITY_Args Tests|Args Tests]]
- [[_COMMUNITY_Vitest Config|Vitest Config]]
- [[_COMMUNITY_Vitest Config Alt|Vitest Config Alt]]
- [[_COMMUNITY_Ancestry Builder|Ancestry Builder]]
- [[_COMMUNITY_Failure Threshold|Failure Threshold]]
- [[_COMMUNITY_Config Schema|Config Schema]]
- [[_COMMUNITY_Dep Type|Dep Type]]
- [[_COMMUNITY_Sync Metadata|Sync Metadata]]
- [[_COMMUNITY_Deferred Work|Deferred Work]]
- [[_COMMUNITY_Community 26|Community 26]]
- [[_COMMUNITY_Community 27|Community 27]]
- [[_COMMUNITY_Community 28|Community 28]]
- [[_COMMUNITY_Community 29|Community 29]]
- [[_COMMUNITY_Community 30|Community 30]]
- [[_COMMUNITY_Community 31|Community 31]]
- [[_COMMUNITY_Community 32|Community 32]]
- [[_COMMUNITY_Community 33|Community 33]]
- [[_COMMUNITY_Community 34|Community 34]]
- [[_COMMUNITY_Community 35|Community 35]]
- [[_COMMUNITY_Community 36|Community 36]]
- [[_COMMUNITY_Community 37|Community 37]]
- [[_COMMUNITY_Community 38|Community 38]]
- [[_COMMUNITY_Community 39|Community 39]]
- [[_COMMUNITY_Community 40|Community 40]]
- [[_COMMUNITY_Community 41|Community 41]]
- [[_COMMUNITY_Community 42|Community 42]]
- [[_COMMUNITY_Community 43|Community 43]]
- [[_COMMUNITY_Community 44|Community 44]]
- [[_COMMUNITY_Community 45|Community 45]]
- [[_COMMUNITY_Community 46|Community 46]]
- [[_COMMUNITY_Community 47|Community 47]]
- [[_COMMUNITY_Community 48|Community 48]]
- [[_COMMUNITY_Community 49|Community 49]]
- [[_COMMUNITY_Community 50|Community 50]]
- [[_COMMUNITY_Community 51|Community 51]]
- [[_COMMUNITY_Community 52|Community 52]]
- [[_COMMUNITY_Community 53|Community 53]]
- [[_COMMUNITY_Community 54|Community 54]]
- [[_COMMUNITY_Community 55|Community 55]]
- [[_COMMUNITY_Community 56|Community 56]]
- [[_COMMUNITY_Community 57|Community 57]]
- [[_COMMUNITY_Community 58|Community 58]]
- [[_COMMUNITY_Community 59|Community 59]]
- [[_COMMUNITY_Community 60|Community 60]]
- [[_COMMUNITY_Community 61|Community 61]]
- [[_COMMUNITY_Community 62|Community 62]]
- [[_COMMUNITY_Community 63|Community 63]]
- [[_COMMUNITY_Community 64|Community 64]]
- [[_COMMUNITY_Community 65|Community 65]]
- [[_COMMUNITY_Community 66|Community 66]]
- [[_COMMUNITY_Community 67|Community 67]]
- [[_COMMUNITY_Community 68|Community 68]]
- [[_COMMUNITY_Community 69|Community 69]]
- [[_COMMUNITY_Community 70|Community 70]]
- [[_COMMUNITY_Community 71|Community 71]]
- [[_COMMUNITY_Community 72|Community 72]]
- [[_COMMUNITY_Community 73|Community 73]]
- [[_COMMUNITY_Community 74|Community 74]]
- [[_COMMUNITY_Community 75|Community 75]]
- [[_COMMUNITY_Community 76|Community 76]]
- [[_COMMUNITY_Community 77|Community 77]]
- [[_COMMUNITY_Community 78|Community 78]]
- [[_COMMUNITY_Community 79|Community 79]]
- [[_COMMUNITY_Community 81|Community 81]]
- [[_COMMUNITY_Community 82|Community 82]]
- [[_COMMUNITY_Community 83|Community 83]]
- [[_COMMUNITY_Community 84|Community 84]]
- [[_COMMUNITY_Community 85|Community 85]]
- [[_COMMUNITY_Community 86|Community 86]]
- [[_COMMUNITY_Community 87|Community 87]]

## God Nodes (most connected - your core abstractions)
1. `Changelog` - 31 edges
2. `[0.1.0] — 2026-05-27` - 28 edges
3. `Glossary` - 21 edges
4. `main()` - 19 edges
5. `run()` - 18 edges
6. `run()` - 18 edges
7. `incomplete()` - 17 edges
8. `[0.2.0] — 2026-05-27` - 17 edges
9. `incomplete()` - 17 edges
10. `[0.2.1] — 2026-05-27` - 16 edges

## Surprising Connections (you probably didn't know these)
- `Issue #004: Incremental GitHub Advisory Sync` --references--> `github-advisory-sync module`  [EXTRACTED]
  docs/issues/004-incremental-github-advisory-sync.md → src/github-advisory-sync.ts
- `GitHub Advisory REST Pagination Strategy` --conceptually_related_to--> `github-advisory-sync module`  [EXTRACTED]
  docs/adr/0001-per-source-fetch-strategy.md → src/github-advisory-sync.ts
- `module responsibilities table` --documents--> `openDb`  [EXTRACTED]
  CLAUDE.md → src/local-db.ts
- `vulnscan architecture doc` --documents--> `runScan`  [EXTRACTED]
  CLAUDE.md → src/scanner.ts
- `database schema notes` --documents--> `pruneStaleAdvisories`  [EXTRACTED]
  CLAUDE.md → src/local-db.ts

## Hyperedges (group relationships)
- **Phase 2 via-field data flow: Ancestry Tracker populates via on Dep, flows through RangeMatcher to Finding, rendered by GroupedOutput** — concept_ancestry_tracker, concept_via_field, concept_grouped_output, issue_002_ancestry_tracking, issue_001_grouped_output [EXTRACTED 0.95]

## Communities (88 total, 14 thin omitted)

### Community 0 - "CLI Entry & Architecture Docs"
Cohesion: 0.05
Nodes (41): SqliteAdvisoryStore, advisoryCount(), AdvisoryRow, getAdvisoriesForPackage(), getAllAdvisories(), mapRowsSafely(), openDb(), rowToAdvisory() (+33 more)

### Community 1 - "CLI Args & Scan Pipeline"
Cohesion: 0.06
Nodes (44): ADR 0001: Per-Source Fetch Strategy, buildSemverRange function (private), matchAffected function, normalizeRawRange function, ancestry module, cli module, Affected Range Match (semver evaluation), Lockfile Ancestry Tracker (via BFS) (+36 more)

### Community 2 - "Advisory Database Layer"
Cohesion: 0.1
Nodes (34): buildAncestryMap(), closeSpy, mockDb, noWarnings, orig, stderrSpy, written, fetchWithRetry() (+26 more)

### Community 3 - "Semver Matching & E2E Tests"
Cohesion: 0.07
Nodes (43): matchAffected tests, vulnscan architecture doc, database schema notes, module responsibilities table, getFailOn, main, safeClose, shouldFail (+35 more)

### Community 4 - "Range Match Logic"
Cohesion: 0.05
Nodes (23): InMemoryAdvisoryStore, advisories, advisory, first, results, second, advisories, cancelFn (+15 more)

### Community 5 - "Output Rendering"
Cohesion: 0.11
Nodes (24): parseArgs(), renderHelp(), run(), safeClose(), Config, DEFAULTS, loadConfig(), config (+16 more)

### Community 6 - "Lockfile Ancestry"
Cohesion: 0.15
Nodes (27): openStore(), matchAffected(), bootstrapDb(), maybeBootstrap(), resolveAssetUrl(), parseArgs(), computeExitCode(), getFailOn() (+19 more)

### Community 7 - "Architecture Decisions (ADRs)"
Cohesion: 0.12
Nodes (24): mapSeverity(), resolveAdvisorySeverity(), result, AdvisoryIdentity, assembleAdvisories(), PackageContribution, SEVERITY_RANK, contributions (+16 more)

### Community 8 - "OSV Sync"
Cohesion: 0.08
Nodes (22): Config, DEFAULTS, config, dir, stderrSpy, VALID_SEVERITIES, validateStalenessHours(), SEVERITY_RANK (+14 more)

### Community 9 - "GitHub Advisory Sync"
Cohesion: 0.1
Nodes (28): [0.2.11] — 2026-05-30, [0.2.12] — 2026-05-31, [0.2.18] — 2026-05-31, [0.2.19] — 2026-05-31, [0.2.20] — 2026-05-31, [0.2.21] — 2026-05-31, [0.2.22] — 2026-05-31, Fixes (+20 more)

### Community 10 - "E2E Test Fixtures"
Cohesion: 0.07
Nodes (27): [0.1.0] — 2026-05-27, Breaking changes, Bug fixes, Internal, Internal, Internal, Internal, Internal (+19 more)

### Community 11 - "Sync Test Helpers"
Cohesion: 0.08
Nodes (24): Advisory, Affected Range Match, Bootstrap, Boundaries, Check, Claude Code Skill, Config File, Deduplication (+16 more)

### Community 12 - "Ancestry Tests"
Cohesion: 0.11
Nodes (17): Advisory, AdvisoryStore, SemverRange, normalizeRawRange(), advisory, advisory2, findings, lodashAdvisory (+9 more)

### Community 13 - "Orchestrator Test Helpers"
Cohesion: 0.11
Nodes (24): [0.2.5] — 2026-05-27, [0.2.6] — 2026-05-27, [0.2.7] — 2026-05-27, Fixes, Fixes, Fixes, Fixes, Fixes (+16 more)

### Community 14 - "Arg Parser Core"
Cohesion: 0.08
Nodes (21): code:block1 (OSV (Google)                          GitHub Advisory Databa), code:block2 (┌───────────────────────────────────────────────────────────), code:block3 (First run:), code:typescript (interface AdvisoryStore {), code:block5 (package-lock.json), code:block6 (computeExitCode(findings, warnings, config):), code:block7 (Defaults hardcoded in config.ts), Configuration layers (+13 more)

### Community 15 - "Renderer Module"
Cohesion: 0.08
Nodes (18): { advisories }, [arg], arrayBufferSpy, baseAffected, buf, { db }, { db, transactionWrapper }, entries (+10 more)

### Community 16 - "Config Tests"
Cohesion: 0.09
Nodes (17): advisories, cancelFn, firstRangeHit, malAdvisory, malformed, malwareItem, mockFetch, multiRangeItem (+9 more)

### Community 17 - "Args Tests"
Cohesion: 0.09
Nodes (22): Claude Code Skill, CLI commands, code:block1 (vulnscan scan .), Config file, Data flow, Failure threshold, Further Notes, GitHub token (+14 more)

### Community 18 - "Vitest Config"
Cohesion: 0.09
Nodes (22): Claude Code Skill, CLI commands, code:block1 (vulnscan scan .), Config file, Data flow, Failure threshold, Further Notes, GitHub token (+14 more)

### Community 19 - "Vitest Config Alt"
Cohesion: 0.23
Nodes (15): Dep, incomplete(), informational(), ScanWarning, w, LockfileRoot, parseLockfile(), PackageEntry (+7 more)

### Community 20 - "Ancestry Builder"
Cohesion: 0.09
Nodes (21): advisories, after, before, database, dbPath, expectedOrder, first, forA (+13 more)

### Community 21 - "Failure Threshold"
Cohesion: 0.09
Nodes (20): Agent skills, AI Integration, Architecture, code:bash (npm test                                    # run all tests ), code:block2 (cli.ts → parseArgs → [scan | check | update | help]), code:json ({), code:typescript (const syncStub = vi.fn().mockResolvedValue([])), code:typescript (const written: string[] = []) (+12 more)

### Community 22 - "Config Schema"
Cohesion: 0.1
Nodes (16): eventsToRanges(), { advisories }, arrayBufferSpy, baseAffected, buf, entries, entry, goEntry (+8 more)

### Community 23 - "Dep Type"
Cohesion: 0.1
Nodes (19): CLI_PATH, db, dbp, deps, dir, __dirname, findings, first (+11 more)

### Community 24 - "Sync Metadata"
Cohesion: 0.12
Nodes (15): Finding, Severity, SEVERITY_RANK, cveFinding, finding1, finding2, ghFinding, ghsaFinding (+7 more)

### Community 25 - "Deferred Work"
Cohesion: 0.1
Nodes (18): CLI_PATH, db, dbp, deps, dir, __dirname, first, isolatedDbPath (+10 more)

### Community 26 - "Community 26"
Cohesion: 0.09
Nodes (17): LockfileV2, PackageEntry, lockfile, map, mapAFirst, mapBFirst, packageJson, packageJsonAFirst (+9 more)

### Community 27 - "Community 27"
Cohesion: 0.15
Nodes (16): CheckInput, checkPackage(), CheckResult, offlineStalenessWarnings(), runScan(), ScanInput, ScanResult, SyncFn (+8 more)

### Community 28 - "Community 28"
Cohesion: 0.11
Nodes (18): advisory1, advisory2, critIdx, finding, findings, highIdx, longTitle, lowIdx (+10 more)

### Community 29 - "Community 29"
Cohesion: 0.12
Nodes (19): [0.2.15] — 2026-05-31, [0.2.16] — 2026-05-31, [0.2.17] — 2026-05-31, Fixes, Fixes, Fixes, Fixes, Fixes (+11 more)

### Community 30 - "Community 30"
Cohesion: 0.11
Nodes (18): advisory1, advisory2, critIdx, finding, findings, highIdx, longTitle, lowIdx (+10 more)

### Community 31 - "Community 31"
Cohesion: 0.18
Nodes (13): advisoryCount(), AdvisoryRow, getAdvisoriesForPackage(), getAllAdvisories(), getLastSyncedAt(), mapRowsSafely(), openDb(), rowToAdvisory() (+5 more)

### Community 32 - "Community 32"
Cohesion: 0.15
Nodes (16): code:bash (npm install -g @catreeo123/vulnscan), code:bash (npm install && npm run build && npm link), code:bash (# Scan current directory (reads package-lock.json)), code:json ({), code:json ({), code:bash (npm test               # run all tests), Configuration, Development (+8 more)

### Community 33 - "Community 33"
Cohesion: 0.13
Nodes (16): [0.0.1] — initial release, [0.1.1] — 2026-05-27, [0.2.23] — 2026-05-31, [0.2.24] — 2026-05-31, [0.2.25] — 2026-05-31, [0.2.26] — 2026-05-31, [0.2.2] — 2026-05-27, [0.2.8] — 2026-05-27 (+8 more)

### Community 34 - "Community 34"
Cohesion: 0.18
Nodes (11): normalizeRawRange(), advisory, advisory2, findings, lodashAdvisory, malAdvisory, multiRangeAdvisory, prereleaseAdvisory (+3 more)

### Community 35 - "Community 35"
Cohesion: 0.17
Nodes (16): [0.2.3] — 2026-05-27, [0.2.4] — 2026-05-27, Fixes, Fixes, Fixes, Fixes, Fixes, Fixes (+8 more)

### Community 36 - "Community 36"
Cohesion: 0.16
Nodes (16): [0.2.10] — 2026-05-29, [0.2.13] — 2026-05-31, [0.2.14] — 2026-05-31, Fixes, Fixes, Fixes, Fixes, Fixes (+8 more)

### Community 37 - "Community 37"
Cohesion: 0.13
Nodes (15): [0.2.0] — 2026-05-27, Fixes, Fixes, Fixes, Fixes, Fixes, Fixes, Fixes (+7 more)

### Community 38 - "Community 38"
Cohesion: 0.13
Nodes (14): code:block1 (Dep    = { name: string; version: string; via?: string }), Further Notes, GitHub Actions snapshot workflow, Grouped output renderer, Implementation Decisions, Incremental GitHub Advisory sync, Lockfile ancestry tracker, Out of Scope (+6 more)

### Community 39 - "Community 39"
Cohesion: 0.21
Nodes (11): eventsToRanges(), getBestId(), OsvAffected, OsvEntry, osvEntryToAdvisories(), OsvEvent, OsvRange, SEVERITY_RANK (+3 more)

### Community 40 - "Community 40"
Cohesion: 0.13
Nodes (14): code:block1 (Dep    = { name: string; version: string; via?: string }), Further Notes, GitHub Actions snapshot workflow, Grouped output renderer, Implementation Decisions, Incremental GitHub Advisory sync, Lockfile ancestry tracker, Out of Scope (+6 more)

### Community 41 - "Community 41"
Cohesion: 0.27
Nodes (11): addSortIndicators(), enableUI(), getNthColumn(), getTable(), getTableBody(), getTableHeader(), loadColumns(), loadData() (+3 more)

### Community 42 - "Community 42"
Cohesion: 0.18
Nodes (10): buildAncestryMap(), LockfileV2, PackageEntry, lockfile, map, mapAFirst, mapBFirst, packageJson (+2 more)

### Community 43 - "Community 43"
Cohesion: 0.17
Nodes (11): Advisory, code:json ({), code:json ({), code:json ({), code:json ({ "introduced": "0.0.0", "fixed": "4.17.21" }), Exit codes, Finding, SemverRange (+3 more)

### Community 44 - "Community 44"
Cohesion: 0.32
Nodes (9): a(), B(), D(), g(), i(), k(), Q(), y() (+1 more)

### Community 45 - "Community 45"
Cohesion: 0.2
Nodes (9): DEFAULT_SOURCE, installSkill(), dest, origStdout, origWrite, skillDir, stderrWrites, stdoutWrites (+1 more)

### Community 46 - "Community 46"
Cohesion: 0.18
Nodes (4): SqliteAdvisoryStore, pruneStaleAdvisories(), upsertAdvisory(), upsertAdvisoryFromFullSync()

### Community 47 - "Community 47"
Cohesion: 0.18
Nodes (10): 1. Run the scan, 2. Parse JSON output, 3. Report warnings (if any), 4. Report findings, Breaking change rule, code:block1 (/vulnscan [path]), code:bash (vulnscan scan <path> --format json), Quick start (+2 more)

### Community 48 - "Community 48"
Cohesion: 0.2
Nodes (9): DEFAULT_SOURCE, installSkill(), dest, origStdout, origWrite, skillDir, stderrWrites, stdoutWrites (+1 more)

### Community 49 - "Community 49"
Cohesion: 0.2
Nodes (8): HelpTopic, KNOWN_BOOLEAN_FLAGS, KNOWN_COMMANDS, KNOWN_FLAGS, ParsedArgs, result, spy, stderrSpy

### Community 50 - "Community 50"
Cohesion: 0.2
Nodes (9): ADR-0002 — AdvisoryStore repository seam, Consequences, Context, Decision, `github-advisory-sync.test.ts`, Pilot results, `scanner.test.ts`, Stumbling block: batch transaction in `osv-sync.ts` (+1 more)

### Community 51 - "Community 51"
Cohesion: 0.2
Nodes (9): code:block1 (resolveAdvisorySeverity(type, label, id):), Further Notes, Implementation Decisions, Out of Scope, PRD: Correctness & hardening fixes from whole-repo review (8 bugs), Problem Statement, Solution, Testing Decisions (+1 more)

### Community 52 - "Community 52"
Cohesion: 0.2
Nodes (8): HelpTopic, KNOWN_BOOLEAN_FLAGS, KNOWN_COMMANDS, KNOWN_FLAGS, ParsedArgs, result, spy, stderrSpy

### Community 53 - "Community 53"
Cohesion: 0.2
Nodes (9): code:block1 (resolveAdvisorySeverity(type, label, id):), Further Notes, Implementation Decisions, Out of Scope, PRD: Correctness & hardening fixes from whole-repo review (8 bugs), Problem Statement, Solution, Testing Decisions (+1 more)

### Community 55 - "Community 55"
Cohesion: 0.22
Nodes (8): { deps }, { deps, warnings }, fixture, v1Fixture, v2Fixture, v2WithTransitive, v3Fixture, w

### Community 56 - "Community 56"
Cohesion: 0.22
Nodes (9): [0.2.1] — 2026-05-27, Fixes, Fixes, Fixes, Fixes, Fixes, Fixes, Fixes (+1 more)

### Community 57 - "Community 57"
Cohesion: 0.22
Nodes (6): inc, incompleteWarning, now, origWrite, store, written

### Community 58 - "Community 58"
Cohesion: 0.25
Nodes (8): [0.2.9] — 2026-05-27, Fixes, Fixes, Fixes, Fixes, Fixes, Fixes, Fixes

### Community 59 - "Community 59"
Cohesion: 0.25
Nodes (7): ADR 0001 — Per-Source Fetch Strategy, Consequences, Context, Decision, GitHub Advisory: REST API pagination, OSV: full dump download, Socket.dev: dropped

### Community 60 - "Community 60"
Cohesion: 0.29
Nodes (5): closeSpy, mockDb, orig, stderrSpy, written

### Community 61 - "Community 61"
Cohesion: 0.29
Nodes (6): Before exploring, read these, code:block1 (/), Domain Docs, File structure, Flag ADR conflicts, Use the glossary's vocabulary

### Community 62 - "Community 62"
Cohesion: 0.38
Nodes (5): Acceptance criteria, Blocked by, code:block1 (/advisories?type=reviewed&ecosystem=npm&per_page=100), code:bash (curl -s "https://api.github.com/advisories?type=reviewed&eco), What to build

### Community 63 - "Community 63"
Cohesion: 0.33
Nodes (5): advisories, advisory, first, results, second

### Community 64 - "Community 64"
Cohesion: 0.33
Nodes (5): 1. What worked, 2. What went wrong (and the lesson each time), 3. Playbook for the next session, Bug-Hunt Convergence Loop — Experience & Playbook, The loop in one paragraph

### Community 65 - "Community 65"
Cohesion: 0.33
Nodes (5): ADR 0003 — Claude Code Skill Self-Registration via `vulnscan skill install`, Consequences, Context, Decision, Rationale

### Community 66 - "Community 66"
Cohesion: 0.53
Nodes (4): Acceptance criteria, Blocked by, Follow-up (not in scope), What to build

### Community 67 - "Community 67"
Cohesion: 0.47
Nodes (4): Acceptance criteria, Blocked by, code:block1 (Dep     = { name: string; version: string; via?: string }), What to build

### Community 68 - "Community 68"
Cohesion: 0.4
Nodes (4): Conventions, Issue tracker: GitHub, When a skill says "fetch the relevant ticket", When a skill says "publish to the issue tracker"

### Community 69 - "Community 69"
Cohesion: 0.6
Nodes (3): Acceptance criteria, Blocked by, What to build

### Community 70 - "Community 70"
Cohesion: 0.7
Nodes (4): goToNext(), goToPrevious(), makeCurrent(), toggleClass()

### Community 71 - "Community 71"
Cohesion: 0.5
Nodes (3): mockBody, mockGunzip, mockWriteStream

### Community 72 - "Community 72"
Cohesion: 0.5
Nodes (3): mockBody, mockGunzip, mockWriteStream

### Community 73 - "Community 73"
Cohesion: 0.5
Nodes (4): Ancestry Map Tests, buildAncestryMap() — BFS transitive dep → root mapping, BFS ancestry traversal — first root in declaration order wins shared dep, npm resolution algorithm — nearest node_modules ancestor wins for nested packages

## Knowledge Gaps
- **692 isolated node(s):** `identity`, `contributions`, `result`, `result`, `store` (+687 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **14 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Changelog` connect `Community 33` to `Community 35`, `Community 36`, `Community 37`, `GitHub Advisory Sync`, `E2E Test Fixtures`, `Orchestrator Test Helpers`, `Community 56`, `Community 58`, `Community 29`?**
  _High betweenness centrality (0.019) - this node is a cross-community bridge._
- **Why does `[0.1.0] — 2026-05-27` connect `E2E Test Fixtures` to `Community 33`, `Community 29`?**
  _High betweenness centrality (0.008) - this node is a cross-community bridge._
- **Why does `run()` connect `Output Rendering` to `Community 45`, `Vitest Config Alt`, `Sync Metadata`, `Community 27`, `Community 60`?**
  _High betweenness centrality (0.006) - this node is a cross-community bridge._
- **What connects `identity`, `contributions`, `result` to the rest of the system?**
  _692 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `CLI Entry & Architecture Docs` be split into smaller, more focused modules?**
  _Cohesion score 0.05 - nodes in this community are weakly interconnected._
- **Should `CLI Args & Scan Pipeline` be split into smaller, more focused modules?**
  _Cohesion score 0.06 - nodes in this community are weakly interconnected._
- **Should `Advisory Database Layer` be split into smaller, more focused modules?**
  _Cohesion score 0.1 - nodes in this community are weakly interconnected._