import { readFileSync, readdirSync, statSync, existsSync, createReadStream } from "node:fs";
import { join, relative, resolve, basename } from "node:path";
import { homedir } from "node:os";
import { createHash } from "node:crypto";
import { DETECTION_RULES, KNOWN_MALICIOUS_HASHES } from "./patterns.js";
import { resolveAllowlistPaths, loadAllowlist, applyAllowlist } from "./allowlist.js";
import type { Finding, SkillReport, ScanResult, DetectionRule, Allowlist } from "./types.js";

const SCAN_EXTENSIONS = /\.(js|ts|mjs|cjs|json|md|txt|yaml|yml|sh|bash|py|toml)$/;
const MAX_FILE_SIZE = 1024 * 1024; // 1MB
const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "build", ".cache"]);

function walkDir(dir: string, files: string[] = []): string[] {
  if (!existsSync(dir)) return files;
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (SKIP_DIRS.has(entry.name)) continue;
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      walkDir(full, files);
    } else if (entry.isFile() && SCAN_EXTENSIONS.test(entry.name)) {
      try {
        if (statSync(full).size <= MAX_FILE_SIZE) {
          files.push(full);
        }
      } catch {
        // skip unreadable
      }
    }
  }
  return files;
}

/** SHA-256 hash a file. Returns null on read error. */
export function hashFile(filePath: string): Promise<string | null> {
  return new Promise((resolve) => {
    const hash = createHash("sha256");
    const stream = createReadStream(filePath);
    stream.on("data", (chunk) => hash.update(chunk));
    stream.on("end", () => resolve(hash.digest("hex")));
    stream.on("error", () => resolve(null));
  });
}

function scanFile(filePath: string, rules: DetectionRule[]): Finding[] {
  const findings: Finding[] = [];
  let content: string;
  try {
    content = readFileSync(filePath, "utf-8");
  } catch {
    return findings;
  }

  const lines = content.split("\n");

  for (const rule of rules) {
    if (rule.fileFilter && !rule.fileFilter.test(filePath)) continue;

    if (rule.multiline) {
      // Test the full file content (handles patterns that span multiple lines).
      // Build a global version of the pattern to find all matches.
      const gFlags = rule.pattern.flags.includes("g") ? rule.pattern.flags : rule.pattern.flags + "g";
      const gPattern = new RegExp(rule.pattern.source, gFlags);
      let m: RegExpExecArray | null;
      while ((m = gPattern.exec(content)) !== null) {
        const lineNum = content.slice(0, m.index).split("\n").length;
        findings.push({
          severity: rule.severity,
          rule: rule.id,
          description: rule.description,
          file: filePath,
          line: lineNum,
          // Truncate match to 60 chars to avoid leaking sensitive context.
          match: m[0].slice(0, 60).replace(/\n/g, "↵"),
        });
      }
    } else {
      // Line-by-line scan: report all matching lines (not just the first).
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i]!;
        if (rule.pattern.test(line)) {
          findings.push({
            severity: rule.severity,
            rule: rule.id,
            description: rule.description,
            file: filePath,
            line: i + 1,
            match: line.trim().slice(0, 60),
          });
        }
      }
    }
  }

  return findings;
}

function calculateScore(findings: Finding[]): number {
  if (findings.length === 0) return 100;
  const weights = { critical: 40, high: 20, medium: 10, low: 3, info: 1 };
  const penalty = findings.reduce((sum, f) => sum + (weights[f.severity] || 0), 0);
  return Math.max(0, 100 - penalty);
}

export interface ScanSkillOptions {
  allowlist?: Allowlist;
}

export async function scanSkill(skillPath: string, options?: ScanSkillOptions): Promise<SkillReport> {
  const name = basename(skillPath);
  const absPath = resolve(skillPath);
  const files = walkDir(absPath);
  const findings: Finding[] = [];

  for (const file of files) {
    // Check SHA-256 hash against known-malicious set.
    const fileHash = await hashFile(file);
    if (fileHash && KNOWN_MALICIOUS_HASHES.has(fileHash)) {
      findings.push({
        severity: "critical",
        rule: "HASH-KNOWN-MALICIOUS",
        description: "File matches known malicious hash (ClawHavoc/AMOS campaign)",
        file: relative(absPath, file),
        match: fileHash.slice(0, 16) + "...",
      });
    }

    const fileFindings = scanFile(file, DETECTION_RULES);
    for (const f of fileFindings) {
      f.file = relative(absPath, f.file);
    }
    findings.push(...fileFindings);
  }

  // Deduplicate: same rule + same file + same line = one finding.
  const seen = new Set<string>();
  const deduplicated = findings.filter((f) => {
    const key = `${f.rule}:${f.file}:${f.line ?? 0}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  // Apply allowlist to suppress known false positives.
  const allowlist = options?.allowlist ?? loadAllowlist(resolveAllowlistPaths(absPath));
  const [filtered, suppressed] = applyAllowlist(deduplicated, allowlist);

  // Sort: critical first
  const order: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  filtered.sort((a, b) => (order[a.severity] ?? 5) - (order[b.severity] ?? 5));

  return {
    name,
    path: absPath,
    findings: filtered,
    scannedFiles: files.length,
    score: calculateScore(filtered),
    suppressed,
  };
}

export function getDefaultSkillPaths(): string[] {
  const paths: string[] = [];
  const home = homedir();

  // ClawHub installed skills
  const clawSkills = join(home, ".openclaw", "skills");
  if (existsSync(clawSkills)) {
    for (const entry of readdirSync(clawSkills, { withFileTypes: true })) {
      if (entry.isDirectory()) {
        paths.push(join(clawSkills, entry.name));
      }
    }
  }

  // npm global skills (OpenClaw built-in)
  const npmSkills = join(home, ".npm-global", "lib", "node_modules", "openclaw", "skills");
  if (existsSync(npmSkills)) {
    for (const entry of readdirSync(npmSkills, { withFileTypes: true })) {
      if (entry.isDirectory()) {
        paths.push(join(npmSkills, entry.name));
      }
    }
  }

  return paths;
}

export interface RunScanOptions {
  skillPaths?: string[];
  allowlist?: Allowlist;
}

export async function runScan(options?: RunScanOptions): Promise<ScanResult> {
  const paths = options?.skillPaths ?? getDefaultSkillPaths();
  const skills: SkillReport[] = [];

  for (const p of paths) {
    skills.push(await scanSkill(p, { allowlist: options?.allowlist }));
  }

  // Sort: worst scores first
  skills.sort((a, b) => a.score - b.score);

  const allFindings = skills.flatMap((s) => s.findings);
  const totalSuppressed = skills.reduce((sum, s) => sum + s.suppressed, 0);

  return {
    timestamp: new Date().toISOString(),
    skillsScanned: skills.length,
    totalFindings: allFindings.length,
    critical: allFindings.filter((f) => f.severity === "critical").length,
    high: allFindings.filter((f) => f.severity === "high").length,
    medium: allFindings.filter((f) => f.severity === "medium").length,
    low: allFindings.filter((f) => f.severity === "low").length,
    info: allFindings.filter((f) => f.severity === "info").length,
    skills,
    suppressed: totalSuppressed,
  };
}
