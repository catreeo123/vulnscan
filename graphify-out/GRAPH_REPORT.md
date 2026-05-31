# Graph Report - security-scan-cli  (2026-05-31)

## Corpus Check
- 65 files · ~76,114 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 871 nodes · 1313 edges · 62 communities (49 shown, 13 thin omitted)
- Extraction: 99% EXTRACTED · 1% INFERRED · 0% AMBIGUOUS · INFERRED: 17 edges (avg confidence: 0.81)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `2b7eff1f`
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
- [[_COMMUNITY_Community 55|Community 55]]
- [[_COMMUNITY_Community 56|Community 56]]
- [[_COMMUNITY_Community 57|Community 57]]
- [[_COMMUNITY_Community 58|Community 58]]
- [[_COMMUNITY_Community 59|Community 59]]
- [[_COMMUNITY_Community 60|Community 60]]
- [[_COMMUNITY_Community 61|Community 61]]

## God Nodes (most connected - your core abstractions)
1. `Changelog` - 27 edges
2. `[0.1.0] — 2026-05-27` - 26 edges
3. `Glossary` - 21 edges
4. `main()` - 19 edges
5. `run()` - 18 edges
6. `incomplete()` - 17 edges
7. `[0.2.0] — 2026-05-27` - 16 edges
8. `informational()` - 15 edges
9. `[0.2.1] — 2026-05-27` - 15 edges
10. `[0.2.10] — 2026-05-29` - 14 edges

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

## Communities (62 total, 13 thin omitted)

### Community 0 - "CLI Entry & Architecture Docs"
Cohesion: 0.06
Nodes (64): buildAncestryMap(), SEVERITY_RANK, fetchWithRetry(), GhAdvisory, ghAdvisoryToAdvisories(), GhVuln, mapSeverity(), parseGhRange() (+56 more)

### Community 1 - "CLI Args & Scan Pipeline"
Cohesion: 0.06
Nodes (51): openStore(), matchAffected(), bootstrapDb(), maybeBootstrap(), resolveAssetUrl(), HelpTopic, KNOWN_BOOLEAN_FLAGS, KNOWN_COMMANDS (+43 more)

### Community 2 - "Advisory Database Layer"
Cohesion: 0.06
Nodes (44): ADR 0001: Per-Source Fetch Strategy, buildSemverRange function (private), matchAffected function, normalizeRawRange function, ancestry module, cli module, Affected Range Match (semver evaluation), Lockfile Ancestry Tracker (via BFS) (+36 more)

### Community 3 - "Semver Matching & E2E Tests"
Cohesion: 0.07
Nodes (43): matchAffected tests, vulnscan architecture doc, database schema notes, module responsibilities table, getFailOn, main, safeClose, shouldFail (+35 more)

### Community 4 - "Range Match Logic"
Cohesion: 0.05
Nodes (25): InMemoryAdvisoryStore, advisories, advisory, first, results, second, eventsToRanges(), { advisories } (+17 more)

### Community 5 - "Output Rendering"
Cohesion: 0.08
Nodes (38): [0.2.3] — 2026-05-27, [0.2.4] — 2026-05-27, [0.2.5] — 2026-05-27, [0.2.6] — 2026-05-27, [0.2.7] — 2026-05-27, Fixes, Fixes, Fixes (+30 more)

### Community 6 - "Lockfile Ancestry"
Cohesion: 0.08
Nodes (24): Advisory, Affected Range Match, Bootstrap, Boundaries, Check, Claude Code Skill, Config File, Deduplication (+16 more)

### Community 7 - "Architecture Decisions (ADRs)"
Cohesion: 0.08
Nodes (25): [0.1.0] — 2026-05-27, Breaking changes, Bug fixes, Internal, Internal, Internal, Internal, Internal (+17 more)

### Community 8 - "OSV Sync"
Cohesion: 0.08
Nodes (17): advisories, cancelFn, firstRangeHit, malAdvisory, malformed, malwareItem, mockFetch, multiRangeItem (+9 more)

### Community 9 - "GitHub Advisory Sync"
Cohesion: 0.08
Nodes (21): code:block1 (OSV (Google)                          GitHub Advisory Databa), code:block2 (┌───────────────────────────────────────────────────────────), code:block3 (First run:), code:typescript (interface AdvisoryStore {), code:block5 (package-lock.json), code:block6 (computeExitCode(findings, warnings, config):), code:block7 (Defaults hardcoded in config.ts), Configuration layers (+13 more)

### Community 10 - "E2E Test Fixtures"
Cohesion: 0.09
Nodes (22): advisories, after, before, database, dbPath, expectedOrder, first, forA (+14 more)

### Community 11 - "Sync Test Helpers"
Cohesion: 0.09
Nodes (22): Claude Code Skill, CLI commands, code:block1 (vulnscan scan .), Config file, Data flow, Failure threshold, Further Notes, GitHub token (+14 more)

### Community 12 - "Ancestry Tests"
Cohesion: 0.09
Nodes (20): Agent skills, AI Integration, Architecture, code:bash (npm test                                    # run all tests ), code:block2 (cli.ts → parseArgs → [scan | check | update | help]), code:json ({), code:typescript (const syncStub = vi.fn().mockResolvedValue([])), code:typescript (const written: string[] = []) (+12 more)

### Community 13 - "Orchestrator Test Helpers"
Cohesion: 0.1
Nodes (19): CLI_PATH, db, dbp, deps, dir, __dirname, findings, first (+11 more)

### Community 14 - "Arg Parser Core"
Cohesion: 0.11
Nodes (18): advisory1, advisory2, critIdx, finding, findings, highIdx, longTitle, lowIdx (+10 more)

### Community 15 - "Renderer Module"
Cohesion: 0.15
Nodes (16): code:bash (npm install -g @catreeo123/vulnscan), code:bash (npm install && npm run build && npm link), code:bash (# Scan current directory (reads package-lock.json)), code:json ({), code:json ({), code:bash (npm test               # run all tests), Configuration, Development (+8 more)

### Community 16 - "Config Tests"
Cohesion: 0.14
Nodes (17): [0.2.15] — 2026-05-31, [0.2.16] — 2026-05-31, [0.2.17] — 2026-05-31, Fixes, Fixes, Fixes, Fixes, Fixes (+9 more)

### Community 17 - "Args Tests"
Cohesion: 0.14
Nodes (17): [0.2.11] — 2026-05-30, [0.2.12] — 2026-05-31, [0.2.14] — 2026-05-31, Fixes, Fixes, Fixes, Fixes, Fixes (+9 more)

### Community 18 - "Vitest Config"
Cohesion: 0.13
Nodes (15): [0.2.0] — 2026-05-27, Fixes, Fixes, Fixes, Fixes, Fixes, Fixes, Fixes (+7 more)

### Community 19 - "Vitest Config Alt"
Cohesion: 0.13
Nodes (14): code:block1 (Dep    = { name: string; version: string; via?: string }), Further Notes, GitHub Actions snapshot workflow, Grouped output renderer, Implementation Decisions, Incremental GitHub Advisory sync, Lockfile ancestry tracker, Out of Scope (+6 more)

### Community 20 - "Ancestry Builder"
Cohesion: 0.27
Nodes (11): addSortIndicators(), enableUI(), getNthColumn(), getTable(), getTableBody(), getTableHeader(), loadColumns(), loadData() (+3 more)

### Community 21 - "Failure Threshold"
Cohesion: 0.32
Nodes (9): a(), B(), D(), g(), i(), k(), Q(), y() (+1 more)

### Community 22 - "Config Schema"
Cohesion: 0.17
Nodes (11): Advisory, code:json ({), code:json ({), code:json ({), code:json ({ "introduced": "0.0.0", "fixed": "4.17.21" }), Exit codes, Finding, SemverRange (+3 more)

### Community 23 - "Dep Type"
Cohesion: 0.23
Nodes (12): [0.2.18] — 2026-05-31, [0.2.19] — 2026-05-31, [0.2.20] — 2026-05-31, [0.2.21] — 2026-05-31, [0.2.22] — 2026-05-31, Fixes, Fixes, Fixes (+4 more)

### Community 24 - "Sync Metadata"
Cohesion: 0.2
Nodes (9): DEFAULT_SOURCE, installSkill(), dest, origStdout, origWrite, skillDir, stderrWrites, stdoutWrites (+1 more)

### Community 25 - "Deferred Work"
Cohesion: 0.18
Nodes (9): LockfileV2, PackageEntry, lockfile, map, mapAFirst, mapBFirst, packageJson, packageJsonAFirst (+1 more)

### Community 26 - "Community 26"
Cohesion: 0.18
Nodes (10): 1. Run the scan, 2. Parse JSON output, 3. Report warnings (if any), 4. Report findings, Breaking change rule, code:block1 (/vulnscan [path]), code:bash (vulnscan scan <path> --format json), Quick start (+2 more)

### Community 27 - "Community 27"
Cohesion: 0.22
Nodes (11): [0.2.10] — 2026-05-29, [0.2.13] — 2026-05-31, Fixes, Fixes, Fixes, Fixes, Fixes, Fixes (+3 more)

### Community 29 - "Community 29"
Cohesion: 0.2
Nodes (9): code:block1 (resolveAdvisorySeverity(type, label, id):), Further Notes, Implementation Decisions, Out of Scope, PRD: Correctness & hardening fixes from whole-repo review (8 bugs), Problem Statement, Solution, Testing Decisions (+1 more)

### Community 30 - "Community 30"
Cohesion: 0.2
Nodes (9): ADR-0002 — AdvisoryStore repository seam, Consequences, Context, Decision, `github-advisory-sync.test.ts`, Pilot results, `scanner.test.ts`, Stumbling block: batch transaction in `osv-sync.ts` (+1 more)

### Community 31 - "Community 31"
Cohesion: 0.2
Nodes (10): [0.2.1] — 2026-05-27, Fixes, Fixes, Fixes, Fixes, Fixes, Fixes, Fixes (+2 more)

### Community 32 - "Community 32"
Cohesion: 0.22
Nodes (6): inc, incompleteWarning, now, origWrite, store, written

### Community 33 - "Community 33"
Cohesion: 0.22
Nodes (8): { deps }, { deps, warnings }, fixture, v1Fixture, v2Fixture, v2WithTransitive, v3Fixture, w

### Community 34 - "Community 34"
Cohesion: 0.22
Nodes (7): cveFinding, finding1, finding2, ghFinding, ghsaFinding, osvFinding, result

### Community 35 - "Community 35"
Cohesion: 0.22
Nodes (8): normalizeRawRange(), advisory, advisory2, findings, lodashAdvisory, malAdvisory, multiRangeAdvisory, prereleaseAdvisory

### Community 36 - "Community 36"
Cohesion: 0.22
Nodes (8): [0.0.1] — initial release, [0.1.1] — 2026-05-27, [0.2.2] — 2026-05-27, [0.2.8] — 2026-05-27, Changelog, Chores, Refactors, Tests

### Community 37 - "Community 37"
Cohesion: 0.25
Nodes (7): ADR 0001 — Per-Source Fetch Strategy, Consequences, Context, Decision, GitHub Advisory: REST API pagination, OSV: full dump download, Socket.dev: dropped

### Community 38 - "Community 38"
Cohesion: 0.25
Nodes (8): [0.2.9] — 2026-05-27, Fixes, Fixes, Fixes, Fixes, Fixes, Fixes, Fixes

### Community 39 - "Community 39"
Cohesion: 0.29
Nodes (6): Before exploring, read these, code:block1 (/), Domain Docs, File structure, Flag ADR conflicts, Use the glossary's vocabulary

### Community 40 - "Community 40"
Cohesion: 0.33
Nodes (5): Acceptance criteria, Blocked by, code:block1 (/advisories?type=reviewed&ecosystem=npm&per_page=100), code:bash (curl -s "https://api.github.com/advisories?type=reviewed&eco), What to build

### Community 41 - "Community 41"
Cohesion: 0.33
Nodes (5): ADR 0003 — Claude Code Skill Self-Registration via `vulnscan skill install`, Consequences, Context, Decision, Rationale

### Community 42 - "Community 42"
Cohesion: 0.7
Nodes (4): goToNext(), goToPrevious(), makeCurrent(), toggleClass()

### Community 43 - "Community 43"
Cohesion: 0.4
Nodes (4): Conventions, Issue tracker: GitHub, When a skill says "fetch the relevant ticket", When a skill says "publish to the issue tracker"

### Community 44 - "Community 44"
Cohesion: 0.4
Nodes (4): Acceptance criteria, Blocked by, Follow-up (not in scope), What to build

### Community 45 - "Community 45"
Cohesion: 0.4
Nodes (4): Acceptance criteria, Blocked by, code:block1 (Dep     = { name: string; version: string; via?: string }), What to build

### Community 46 - "Community 46"
Cohesion: 0.5
Nodes (3): mockBody, mockGunzip, mockWriteStream

### Community 47 - "Community 47"
Cohesion: 0.5
Nodes (3): Acceptance criteria, Blocked by, What to build

### Community 48 - "Community 48"
Cohesion: 0.5
Nodes (4): Ancestry Map Tests, buildAncestryMap() — BFS transitive dep → root mapping, BFS ancestry traversal — first root in declaration order wins shared dep, npm resolution algorithm — nearest node_modules ancestor wins for nested packages

## Knowledge Gaps
- **463 isolated node(s):** `HelpTopic`, `ParsedArgs`, `KNOWN_FLAGS`, `KNOWN_BOOLEAN_FLAGS`, `KNOWN_COMMANDS` (+458 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **13 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Changelog` connect `Community 36` to `Output Rendering`, `Community 38`, `Architecture Decisions (ADRs)`, `Config Tests`, `Args Tests`, `Vitest Config`, `Dep Type`, `Community 27`, `Community 31`?**
  _High betweenness centrality (0.025) - this node is a cross-community bridge._
- **Why does `run()` connect `CLI Args & Scan Pipeline` to `Sync Metadata`, `CLI Entry & Architecture Docs`?**
  _High betweenness centrality (0.011) - this node is a cross-community bridge._
- **Why does `w` connect `Failure Threshold` to `CLI Entry & Architecture Docs`?**
  _High betweenness centrality (0.010) - this node is a cross-community bridge._
- **What connects `HelpTopic`, `ParsedArgs`, `KNOWN_FLAGS` to the rest of the system?**
  _463 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `CLI Entry & Architecture Docs` be split into smaller, more focused modules?**
  _Cohesion score 0.06 - nodes in this community are weakly interconnected._
- **Should `CLI Args & Scan Pipeline` be split into smaller, more focused modules?**
  _Cohesion score 0.06 - nodes in this community are weakly interconnected._
- **Should `Advisory Database Layer` be split into smaller, more focused modules?**
  _Cohesion score 0.06 - nodes in this community are weakly interconnected._