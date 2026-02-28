# NEXT_ACTIONS (AAHP)

## Status Summary

| Status  | Count |
|---------|-------|
| Done    | 5     |
| Ready   | 1     |
| Blocked | 0     |

---

## Ready - Work These Next

### T-006: Add CI workflow (lint/test) and release checklist
**Priority:** medium | **GitHub:** elvatis/clawhub-scanner#1

**Goal:** Set up GitHub Actions CI with lint and test steps. Add release checklist.

**Context:** A CI workflow and release checklist were already created in T-001, but this task (from GitHub issue #1) may need verification or updates to the existing setup.

**What to do:**
- Verify `.github/workflows/` CI configuration is correct and runs on push/PR
- Ensure lint, type-check, and test steps are all included
- Verify `RELEASE_CHECKLIST.md` is up to date
- Close GitHub issue #1 if already satisfied by T-001

**Files:** `.github/workflows/ci.yml`, `RELEASE_CHECKLIST.md`, `package.json`

**Definition of done:** CI runs successfully on push/PR, release checklist is complete and accurate.

---

## Blocked

(none)

---

## Recently Completed

| Task  | Title                                            | Completed  |
|-------|--------------------------------------------------|------------|
| T-005 | Expand indicators list and rule tuning           | 2026-02-28 |
| T-004 | Add allowlist for common false positives         | 2026-02-28 |
| T-001 | Add CI workflow (lint/test) and release checklist | 2026-02-27 |
| T-002 | Expand IoC indicators list and rule tuning       | 2026-02-27 |
| T-003 | Add allowlist for common false positives         | 2026-02-27 |
