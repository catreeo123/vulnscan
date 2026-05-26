## What to build

Eliminate the 3–5 minute cold-start for new users. When no local database exists, automatically download a weekly pre-built gzip-compressed SQLite snapshot (~15–18 MB), decompress it to the configured database path, and proceed with the scan.

**This issue covers the downloader module and CLI wiring only.** The GitHub Actions workflow for building and uploading the snapshot is a follow-up that requires a GitHub remote to be configured — defer it.

The snapshot downloader module:
1. Emits a progress message to stderr
2. Downloads from a configured URL (read from `VULNSCAN_SNAPSHOT_URL` env var; there is no hardcoded default until a GitHub remote and release tag are established)
3. Decompresses the gzip stream to the database path using Node's built-in `zlib`
4. On any error, throws a sentinel that the CLI catches and falls back to full sync

CLI flow on first run:
- If database file does not exist AND `VULNSCAN_SNAPSHOT_URL` is set → attempt snapshot download
- If download fails OR `VULNSCAN_SNAPSHOT_URL` is unset → fall back to `vulnscan update` (full sync)

## Acceptance criteria

- [ ] First run with no local DB and `VULNSCAN_SNAPSHOT_URL` set triggers snapshot download with progress message to stderr
- [ ] Snapshot is gzip-decompressed and placed at the configured database path
- [ ] Scan proceeds normally after successful download
- [ ] On download failure, falls back to full sync automatically (no crash)
- [ ] `VULNSCAN_SNAPSHOT_URL` unset → skip snapshot attempt, go straight to full sync
- [ ] Happy-path test: file exists at expected path after download from a mock HTTP server serving a gzip-compressed SQLite fixture
- [ ] Error-path test: server returns 500 → sentinel thrown → caller falls back

## Blocked by

None - can start immediately

## Follow-up (not in scope)

Once a GitHub remote exists: create `.github/workflows/rebuild-snapshot.yml` — weekly schedule, runs `vulnscan update`, gzip-compresses the DB, uploads as a release asset. Set `VULNSCAN_SNAPSHOT_URL` constant to the public download URL.
