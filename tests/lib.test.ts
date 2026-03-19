import { describe, it, expect } from "vitest";
import {
  runScan,
  scanSkill,
  getDefaultSkillPaths,
  hashFile,
  loadAllowlist,
  resolveAllowlistPaths,
  applyAllowlist,
  isSuppressed,
  printReport,
  formatJson,
} from "../src/index.js";
import type { ScanResult, SkillReport, Finding, Allowlist } from "../src/index.js";

describe("programmatic API exports", () => {
  it("exports runScan as a function", () => {
    expect(typeof runScan).toBe("function");
  });

  it("exports scanSkill as a function", () => {
    expect(typeof scanSkill).toBe("function");
  });

  it("exports getDefaultSkillPaths as a function", () => {
    expect(typeof getDefaultSkillPaths).toBe("function");
  });

  it("exports hashFile as a function", () => {
    expect(typeof hashFile).toBe("function");
  });

  it("exports loadAllowlist as a function", () => {
    expect(typeof loadAllowlist).toBe("function");
  });

  it("exports resolveAllowlistPaths as a function", () => {
    expect(typeof resolveAllowlistPaths).toBe("function");
  });

  it("exports applyAllowlist as a function", () => {
    expect(typeof applyAllowlist).toBe("function");
  });

  it("exports isSuppressed as a function", () => {
    expect(typeof isSuppressed).toBe("function");
  });

  it("exports printReport as a function", () => {
    expect(typeof printReport).toBe("function");
  });

  it("exports formatJson as a function", () => {
    expect(typeof formatJson).toBe("function");
  });

  it("scanSkill returns a SkillReport with expected shape", async () => {
    const result = await scanSkill(".");
    expect(result).toHaveProperty("name");
    expect(result).toHaveProperty("path");
    expect(result).toHaveProperty("findings");
    expect(result).toHaveProperty("scannedFiles");
    expect(result).toHaveProperty("score");
    expect(result).toHaveProperty("suppressed");
    expect(Array.isArray(result.findings)).toBe(true);
    expect(typeof result.score).toBe("number");
    expect(result.score).toBeGreaterThanOrEqual(0);
    expect(result.score).toBeLessThanOrEqual(100);
  });

  it("formatJson produces valid JSON from a minimal ScanResult", () => {
    const minimal: ScanResult = {
      timestamp: new Date().toISOString(),
      skillsScanned: 0,
      totalFindings: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
      skills: [],
      suppressed: 0,
    };
    const json = formatJson(minimal);
    expect(() => JSON.parse(json)).not.toThrow();
    const parsed = JSON.parse(json) as ScanResult;
    expect(parsed.skillsScanned).toBe(0);
  });

  it("applyAllowlist accepts typed Allowlist and returns tuple", () => {
    const findings: Finding[] = [
      { severity: "high", rule: "EVAL-USAGE", description: "eval detected", file: "test.js", line: 1 },
    ];
    const allowlist: Allowlist = {
      entries: [{ rule: "EVAL-USAGE" }],
    };
    const [kept, suppressed] = applyAllowlist(findings, allowlist);
    expect(kept).toHaveLength(0);
    expect(suppressed).toBe(1);
  });

  it("getDefaultSkillPaths returns an array", () => {
    const paths = getDefaultSkillPaths();
    expect(Array.isArray(paths)).toBe(true);
  });
});
