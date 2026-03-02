# NEXT_ACTIONS - clawhub-scanner

## Ready - Work These Next

### T-007: Implement `update` command for threat intelligence feeds [high] (issue #4)
- **Goal:** Let users refresh IoC data (C2 IPs, domains, hashes) without upgrading the npm package
- **Context:** The CLAUDE.md spec requires `clawhub-scanner update` but it is not implemented. All IoCs are hardcoded in `src/indicators.ts`. The ClawHavoc campaign is actively evolving - new C2 infrastructure appears regularly, so a static list becomes stale fast.
- **What to do:**
  1. Host a `threat-feed.json` file (GitHub raw or CDN) containing IoC arrays in the same shape as `indicators.ts` exports
  2. Add a local cache at `~/.config/clawhub-scanner/threat-feed.json` with a timestamp
  3. Implement `update` subcommand in `src/index.ts` that fetches the remote feed and writes the local cache
  4. Modify `scanner.ts` to merge hardcoded indicators with the cached feed at scan time
  5. Add `--offline` flag to skip feed loading
  6. Add tests with a mock HTTP server
- **Files:** `src/index.ts`, `src/indicators.ts`, `src/scanner.ts`, `src/types.ts`, `tests/update.test.ts` (new)
- **Definition of Done:**
  - [ ] `clawhub-scanner update` fetches remote feed and caches locally
  - [ ] Scanner merges cached feed with built-in indicators
  - [ ] Graceful fallback when offline or feed unreachable
  - [ ] Tests cover fetch, cache, merge, and offline scenarios
  - [ ] README documents the `update` command

### T-008: Export programmatic API and remove unused `glob` dependency [high] (issue #5)
- **Goal:** Make the scanner usable as a library (not just CLI) for CI pipelines, IDE plugins, and other tooling
- **Context:** `package.json` main points to `dist/index.js` which calls `program.parse()` at the top level - importing it runs the CLI. There is no documented library entry point. Also, the `glob` npm dependency is listed but never imported anywhere - the project uses a custom `walkDir()` instead.
- **What to do:**
  1. Create `src/lib.ts` exporting `scanSkill`, `runScan`, types, and utility functions
  2. Update `package.json`: set `"main"` to `dist/lib.js`, add `"exports"` field with `"."` for lib and `"./cli"` for CLI
  3. Keep `"bin"` pointing to `dist/index.js` (CLI entry)
  4. Remove `glob` from dependencies in `package.json`
  5. Add a test that imports from the library entry point
  6. Document programmatic usage in README
- **Files:** `src/lib.ts` (new), `src/index.ts`, `package.json`, `README.md`, `tests/lib.test.ts` (new)
- **Definition of Done:**
  - [ ] `import { scanSkill, runScan } from '@elvatis_com/clawhub-scanner'` works
  - [ ] CLI still works via `npx clawhub-scanner scan`
  - [ ] `glob` dependency removed
  - [ ] Programmatic usage documented in README
  - [ ] Tests verify library exports

### T-009: Add reporter tests and CI code coverage threshold [medium] (issue #6)
- **Goal:** Close the test coverage gap on the reporter module and prevent future regression
- **Context:** `src/reporter.ts` has zero test coverage - it is the only source module without dedicated tests. The CI pipeline runs tests but does not measure or enforce coverage. The project has 136 tests across 3 files but reporter formatting (colored output, JSON, badges, score display) is entirely untested.
- **What to do:**
  1. Create `tests/reporter.test.ts` with tests for `printReport()` and `formatJson()`
  2. Test edge cases: zero findings, all-critical, mixed severities, suppressed counts, empty skill list
  3. Verify JSON output schema matches `ScanResult` type
  4. Add `--coverage` to the vitest config and set a minimum threshold (e.g., 85%)
  5. Update `ci.yml` to include coverage in the test step
- **Files:** `tests/reporter.test.ts` (new), `vitest.config.ts` or `package.json` (vitest config), `.github/workflows/ci.yml`
- **Definition of Done:**
  - [ ] Reporter module has dedicated test file with 10+ tests
  - [ ] Coverage report generated in CI
  - [ ] Coverage threshold enforced (build fails if below threshold)
  - [ ] All existing tests still pass

### T-010: Replace placeholder malicious hashes with real IoCs [medium] (issue #7)
- **Goal:** Make the `HASH-KNOWN-MALICIOUS` detection rule functional against real threats
- **Context:** All 12 entries in `KNOWN_MALICIOUS_HASHES` are synthetic (`a1b2c3d4...`, `aabb0011...`). The hash check runs on every file but can never match real malware. For the scanner to deliver on its promise of detecting ClawHavoc samples, it needs real SHA-256 hashes from actual malicious skills.
- **What to do:**
  1. Research publicly disclosed ClawHavoc/AMOS sample hashes from Snyk, VirusTotal, or MITRE reports
  2. Replace placeholder hashes in `src/indicators.ts` with verified real hashes
  3. Add source attribution comments for each hash (where it was reported)
  4. If real hashes are not yet publicly available, document the hash format and add a contribution guide for community submissions
  5. Update tests to use at least one real hash or a well-documented test hash
- **Files:** `src/indicators.ts`, `tests/scanner.test.ts`
- **Definition of Done:**
  - [ ] Placeholder hashes replaced with real or well-documented hashes
  - [ ] Each hash has a source comment
  - [ ] Hash detection test updated accordingly
  - [ ] README or CONTRIBUTING.md describes how to submit new hashes

### T-011: Add `--scan-path` CLI option and fix `--output` file format bug [low] (issue #8)
- **Goal:** Let users scan arbitrary directories and fix the no-op ternary in file output
- **Context:** The CLI only supports `--skill <dir>` (single skill) or default paths. Users with custom OpenClaw setups or CI pipelines scanning skill repos before publish cannot specify custom scan directories. Additionally, `src/index.ts` line 72 has `opts.json ? formatJson(result) : formatJson(result)` - both branches produce JSON, making the ternary pointless. File output should respect the `--json` flag.
- **What to do:**
  1. Add `--scan-path <dir...>` option to the `scan` command (repeatable, accepts multiple directories)
  2. Pass custom paths to `runScan()` as `skillPaths`
  3. Fix line 72: non-JSON file output should use `formatText()` or similar human-readable format
  4. Add tests for custom scan paths and file output format
- **Files:** `src/index.ts`, `src/reporter.ts`, `tests/scanner.test.ts`
- **Definition of Done:**
  - [ ] `clawhub-scanner scan --scan-path ./my-skills --scan-path ./other-skills` works
  - [ ] `--output report.txt` writes human-readable text (without `--json`)
  - [ ] `--output report.json --json` writes JSON
  - [ ] Tests cover custom path scanning and both output formats

---

## Blocked

(none)

---

## Recently Completed

| Task  | Title                                            | Completed  |
|-------|--------------------------------------------------|------------|
| T-006 | Add CI workflow (lint/test) and release checklist | 2026-02-28 |
| T-005 | Expand indicators list and rule tuning           | 2026-02-28 |
| T-004 | Add allowlist for common false positives         | 2026-02-28 |
| T-001 | Add CI workflow (lint/test) and release checklist | 2026-02-27 |
| T-002 | Expand IoC indicators list and rule tuning       | 2026-02-27 |
