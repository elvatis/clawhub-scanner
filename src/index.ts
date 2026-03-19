/**
 * clawhub-scanner — Programmatic API
 *
 * Usage:
 *   import { runScan, scanSkill, getDefaultSkillPaths } from '@elvatis_com/clawhub-scanner';
 *
 *   const result = await runScan();
 *   const report = await scanSkill('/path/to/skill');
 */

// Core scan functions
export { runScan, scanSkill, getDefaultSkillPaths, hashFile } from "./scanner.js";
export type { ScanSkillOptions, RunScanOptions } from "./scanner.js";

// Allowlist helpers
export { loadAllowlist, resolveAllowlistPaths, applyAllowlist, isSuppressed } from "./allowlist.js";

// Reporter helpers
export { printReport, formatJson } from "./reporter.js";

// All public types
export type {
  Severity,
  Finding,
  SkillReport,
  ScanResult,
  AllowlistEntry,
  Allowlist,
  DetectionRule,
} from "./types.js";
