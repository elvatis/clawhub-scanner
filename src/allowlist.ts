import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import type { Allowlist, AllowlistEntry, Finding } from "./types.js";

const ALLOWLIST_FILENAME = ".clawhub-allowlist.json";

/** Resolve allowlist file paths (skill-local, then global). */
export function resolveAllowlistPaths(skillPath?: string): string[] {
  const paths: string[] = [];
  if (skillPath) {
    paths.push(join(skillPath, ALLOWLIST_FILENAME));
  }
  paths.push(join(homedir(), ".config", "clawhub-scanner", "allowlist.json"));
  return paths;
}

/** Load and merge allowlists from multiple paths. Invalid files are silently skipped. */
export function loadAllowlist(paths: string[]): Allowlist {
  const entries: AllowlistEntry[] = [];
  for (const p of paths) {
    if (!existsSync(p)) continue;
    try {
      const raw = readFileSync(p, "utf-8");
      const parsed = JSON.parse(raw);
      const list: AllowlistEntry[] = Array.isArray(parsed) ? parsed : parsed.entries ?? [];
      for (const entry of list) {
        if (typeof entry.rule === "string") {
          entries.push({
            rule: entry.rule,
            file: typeof entry.file === "string" ? entry.file : undefined,
            reason: typeof entry.reason === "string" ? entry.reason : undefined,
          });
        }
      }
    } catch {
      // Skip unparseable files
    }
  }
  return { entries };
}

/** Check if a file path matches a simple glob pattern (supports * and **). */
function matchFilePattern(pattern: string, filePath: string): boolean {
  // Normalize separators
  const normalized = filePath.replace(/\\/g, "/");
  const pat = pattern.replace(/\\/g, "/");

  // Convert glob to regex
  const regexStr = pat
    .replace(/[.+^${}()|[\]]/g, "\\$&") // Escape regex special chars except * and ?
    .replace(/\*\*/g, "\0")              // Temp placeholder for **
    .replace(/\*/g, "[^/]*")             // * matches within a single path segment
    .replace(/\0/g, ".*")               // ** matches across path segments
    .replace(/\?/g, "[^/]");            // ? matches single char

  return new RegExp(`^${regexStr}$`).test(normalized);
}

/** Check whether a finding is suppressed by any allowlist entry. */
export function isSuppressed(finding: Finding, allowlist: Allowlist): boolean {
  for (const entry of allowlist.entries) {
    if (entry.rule !== "*" && entry.rule !== finding.rule) continue;
    // If no file pattern, the rule match alone is sufficient.
    if (!entry.file) return true;
    // Match the file pattern against the finding's file path.
    if (matchFilePattern(entry.file, finding.file)) return true;
  }
  return false;
}

/** Filter findings through the allowlist, returning [kept, suppressedCount]. */
export function applyAllowlist(
  findings: Finding[],
  allowlist: Allowlist,
): [Finding[], number] {
  if (allowlist.entries.length === 0) return [findings, 0];
  let suppressed = 0;
  const kept = findings.filter((f) => {
    if (isSuppressed(f, allowlist)) {
      suppressed++;
      return false;
    }
    return true;
  });
  return [kept, suppressed];
}
