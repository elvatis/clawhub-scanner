import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { formatJson, printReport } from "../src/reporter.js";
import type { ScanResult, SkillReport, Finding } from "../src/types.js";

// ── Helpers ──────────────────────────────────────────────────────────────────

function makeSkill(overrides: Partial<SkillReport> = {}): SkillReport {
  return {
    name: "test-skill",
    path: "/skills/test-skill",
    findings: [],
    scannedFiles: 5,
    score: 100,
    suppressed: 0,
    ...overrides,
  };
}

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    severity: "high",
    rule: "EXEC-EVAL",
    description: "Dynamic code execution via eval()",
    file: "index.js",
    line: 3,
    match: 'eval("payload")',
    ...overrides,
  };
}

function makeResult(overrides: Partial<ScanResult> = {}): ScanResult {
  return {
    timestamp: "2026-02-01T12:00:00.000Z",
    skillsScanned: 1,
    totalFindings: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    skills: [makeSkill()],
    suppressed: 0,
    ...overrides,
  };
}

// ── formatJson tests ──────────────────────────────────────────────────────────

describe("formatJson", () => {
  it("returns valid JSON string", () => {
    const result = makeResult();
    const json = formatJson(result);
    expect(() => JSON.parse(json)).not.toThrow();
  });

  it("JSON output contains all top-level ScanResult fields", () => {
    const result = makeResult({ skillsScanned: 3, totalFindings: 7 });
    const parsed = JSON.parse(formatJson(result)) as ScanResult;
    expect(parsed.skillsScanned).toBe(3);
    expect(parsed.totalFindings).toBe(7);
    expect(parsed.timestamp).toBe("2026-02-01T12:00:00.000Z");
    expect(Array.isArray(parsed.skills)).toBe(true);
  });

  it("JSON is pretty-printed with 2-space indent", () => {
    const json = formatJson(makeResult());
    // Pretty JSON has newlines and spaces
    expect(json).toContain("\n");
    expect(json).toContain("  ");
  });

  it("serialises nested findings correctly", () => {
    const finding = makeFinding({ rule: "C2-KNOWN-IP", severity: "critical", line: 42 });
    const skill = makeSkill({ findings: [finding], score: 20 });
    const result = makeResult({ skills: [skill], critical: 1, totalFindings: 1 });
    const parsed = JSON.parse(formatJson(result)) as ScanResult;
    expect(parsed.skills[0]!.findings[0]!.rule).toBe("C2-KNOWN-IP");
    expect(parsed.skills[0]!.findings[0]!.severity).toBe("critical");
    expect(parsed.skills[0]!.findings[0]!.line).toBe(42);
  });

  it("handles result with zero skills", () => {
    const result = makeResult({ skills: [], skillsScanned: 0 });
    const parsed = JSON.parse(formatJson(result)) as ScanResult;
    expect(parsed.skills).toHaveLength(0);
    expect(parsed.skillsScanned).toBe(0);
  });

  it("handles result with suppressed count", () => {
    const result = makeResult({ suppressed: 5 });
    const parsed = JSON.parse(formatJson(result)) as ScanResult;
    expect(parsed.suppressed).toBe(5);
  });

  it("serialises finding without optional match field", () => {
    const finding: Finding = {
      severity: "medium",
      rule: "NET-TOR",
      description: "Tor hidden service access",
      file: "net.js",
      line: 10,
      // no match field
    };
    const skill = makeSkill({ findings: [finding] });
    const result = makeResult({ skills: [skill], medium: 1, totalFindings: 1 });
    const parsed = JSON.parse(formatJson(result)) as ScanResult;
    expect(parsed.skills[0]!.findings[0]!.match).toBeUndefined();
  });

  it("serialises finding without optional line field", () => {
    const finding: Finding = {
      severity: "low",
      rule: "EVASION-DEBUGGER",
      description: "Debugger statement",
      file: "app.js",
      // no line field
    };
    const skill = makeSkill({ findings: [finding] });
    const result = makeResult({ skills: [skill], low: 1, totalFindings: 1 });
    const parsed = JSON.parse(formatJson(result)) as ScanResult;
    expect(parsed.skills[0]!.findings[0]!.line).toBeUndefined();
  });

  it("handles multiple skills with mixed findings", () => {
    const cleanSkill = makeSkill({ name: "safe-skill", score: 100 });
    const badSkill = makeSkill({
      name: "bad-skill",
      score: 10,
      findings: [
        makeFinding({ severity: "critical", rule: "C2-KNOWN-IP" }),
        makeFinding({ severity: "high", rule: "EXEC-EVAL" }),
      ],
    });
    const result = makeResult({
      skills: [cleanSkill, badSkill],
      skillsScanned: 2,
      totalFindings: 2,
      critical: 1,
      high: 1,
    });
    const parsed = JSON.parse(formatJson(result)) as ScanResult;
    expect(parsed.skills).toHaveLength(2);
    expect(parsed.skills[1]!.name).toBe("bad-skill");
    expect(parsed.skills[1]!.findings).toHaveLength(2);
  });

  it("round-trips a full ScanResult without data loss", () => {
    const original = makeResult({
      skillsScanned: 2,
      totalFindings: 3,
      critical: 1,
      high: 1,
      medium: 1,
      low: 0,
      info: 0,
      suppressed: 2,
      skills: [
        makeSkill({
          name: "skill-a",
          score: 30,
          suppressed: 2,
          findings: [
            makeFinding({ severity: "critical" }),
            makeFinding({ severity: "high" }),
            makeFinding({ severity: "medium" }),
          ],
        }),
      ],
    });
    const parsed = JSON.parse(formatJson(original)) as ScanResult;
    expect(parsed.critical).toBe(original.critical);
    expect(parsed.suppressed).toBe(original.suppressed);
    expect(parsed.skills[0]!.score).toBe(30);
    expect(parsed.skills[0]!.findings).toHaveLength(3);
  });
});

// ── printReport (text output) tests ──────────────────────────────────────────

describe("printReport", () => {
  let consoleSpy: ReturnType<typeof vi.spyOn>;
  let captured: string[];

  beforeEach(() => {
    captured = [];
    consoleSpy = vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
      // Strip ANSI codes for assertion clarity
      const line = args.map(String).join(" ").replace(/\x1b\[[0-9;]*m/g, "");
      captured.push(line);
    });
  });

  afterEach(() => {
    consoleSpy.mockRestore();
  });

  it("prints the report header", () => {
    printReport(makeResult());
    expect(captured.some((l) => l.includes("ClawHub Security Scan Report"))).toBe(true);
  });

  it("prints the timestamp", () => {
    printReport(makeResult({ timestamp: "2026-02-01T12:00:00.000Z" }));
    expect(captured.some((l) => l.includes("2026-02-01T12:00:00.000Z"))).toBe(true);
  });

  it("shows CLEAN badge for skill with no findings", () => {
    printReport(makeResult({ skills: [makeSkill({ findings: [], score: 100 })] }));
    expect(captured.some((l) => l.includes("CLEAN") || l.includes("No issues found"))).toBe(true);
  });

  it("shows critical warning for results with critical findings", () => {
    const skill = makeSkill({
      findings: [makeFinding({ severity: "critical", rule: "C2-KNOWN-IP" })],
      score: 5,
    });
    printReport(makeResult({ skills: [skill], critical: 1, totalFindings: 1 }));
    expect(
      captured.some((l) => l.includes("CRITICAL") || l.includes("Immediate action")),
    ).toBe(true);
  });

  it("shows high-severity warning for high-only findings", () => {
    const skill = makeSkill({
      findings: [makeFinding({ severity: "high" })],
      score: 40,
    });
    printReport(makeResult({ skills: [skill], high: 1, totalFindings: 1 }));
    expect(
      captured.some((l) => l.includes("high") || l.includes("High-severity")),
    ).toBe(true);
  });

  it("shows all-clear message when no findings", () => {
    printReport(makeResult({ totalFindings: 0, skills: [] }));
    expect(captured.some((l) => l.includes("All clear") || l.includes("No security issues"))).toBe(true);
  });

  it("prints finding rule ID for each finding", () => {
    const skill = makeSkill({
      findings: [makeFinding({ rule: "EXEC-EVAL" })],
      score: 60,
    });
    printReport(makeResult({ skills: [skill], high: 1, totalFindings: 1 }));
    expect(captured.some((l) => l.includes("EXEC-EVAL"))).toBe(true);
  });

  it("prints finding description", () => {
    const skill = makeSkill({
      findings: [makeFinding({ description: "Dynamic code execution via eval()" })],
      score: 60,
    });
    printReport(makeResult({ skills: [skill], high: 1, totalFindings: 1 }));
    expect(captured.some((l) => l.includes("Dynamic code execution via eval()"))).toBe(true);
  });

  it("prints skill name in output", () => {
    const skill = makeSkill({ name: "my-custom-skill", findings: [], score: 100 });
    printReport(makeResult({ skills: [skill] }));
    expect(captured.some((l) => l.includes("my-custom-skill"))).toBe(true);
  });

  it("prints file and line location for findings", () => {
    const skill = makeSkill({
      findings: [makeFinding({ file: "scripts/run.js", line: 17 })],
      score: 50,
    });
    printReport(makeResult({ skills: [skill], high: 1, totalFindings: 1 }));
    expect(captured.some((l) => l.includes("scripts/run.js") && l.includes("17"))).toBe(true);
  });

  it("prints match snippet when present", () => {
    const skill = makeSkill({
      findings: [makeFinding({ match: 'eval("injected-payload")' })],
      score: 50,
    });
    printReport(makeResult({ skills: [skill], high: 1, totalFindings: 1 }));
    expect(captured.some((l) => l.includes('eval("injected-payload")'))).toBe(true);
  });

  it("prints suppressed count when non-zero", () => {
    const skill = makeSkill({ suppressed: 3 });
    printReport(makeResult({ skills: [skill], suppressed: 3 }));
    expect(captured.some((l) => l.includes("3"))).toBe(true);
  });

  it("prints low/medium message for low-severity-only findings", () => {
    const skill = makeSkill({
      findings: [makeFinding({ severity: "medium", rule: "EVASION-DEBUGGER" })],
      score: 75,
    });
    printReport(
      makeResult({ skills: [skill], medium: 1, totalFindings: 1, critical: 0, high: 0 }),
    );
    expect(
      captured.some((l) => l.includes("low") || l.includes("medium") || l.includes("Review")),
    ).toBe(true);
  });

  it("calls console.log at least once (smoke test)", () => {
    printReport(makeResult());
    expect(consoleSpy).toHaveBeenCalled();
  });
});

// ── Markdown format (via formatJson as JSON is the only programmatic format) ─

describe("output format consistency", () => {
  it("formatJson output matches re-serialised JSON", () => {
    const result = makeResult({ skillsScanned: 2, totalFindings: 0 });
    const json1 = formatJson(result);
    const json2 = JSON.stringify(JSON.parse(json1), null, 2);
    expect(json1).toBe(json2);
  });

  it("formatJson severity counts are consistent with findings array", () => {
    const critical = makeFinding({ severity: "critical" });
    const high = makeFinding({ severity: "high" });
    const skill = makeSkill({ findings: [critical, high], score: 20 });
    const result = makeResult({
      skills: [skill],
      critical: 1,
      high: 1,
      totalFindings: 2,
    });
    const parsed = JSON.parse(formatJson(result)) as ScanResult;
    expect(parsed.critical + parsed.high + parsed.medium + parsed.low + parsed.info).toBe(
      parsed.totalFindings,
    );
  });

  it("formatJson timestamp is preserved as-is", () => {
    const ts = "2026-03-01T08:30:00.000Z";
    const result = makeResult({ timestamp: ts });
    const parsed = JSON.parse(formatJson(result)) as ScanResult;
    expect(parsed.timestamp).toBe(ts);
  });
});
