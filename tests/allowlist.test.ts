import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdirSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  loadAllowlist,
  isSuppressed,
  applyAllowlist,
} from "../src/allowlist.js";
import { scanSkill } from "../src/scanner.js";
import type { Finding, Allowlist } from "../src/types.js";

const TEST_DIR = join(tmpdir(), "clawhub-allowlist-test-" + Date.now());

beforeAll(() => {
  mkdirSync(TEST_DIR, { recursive: true });
});

afterAll(() => {
  rmSync(TEST_DIR, { recursive: true, force: true });
});

function createSkill(name: string, files: Record<string, string>): string {
  const dir = join(TEST_DIR, name);
  mkdirSync(dir, { recursive: true });
  for (const [path, content] of Object.entries(files)) {
    const full = join(dir, path);
    mkdirSync(join(full, ".."), { recursive: true });
    writeFileSync(full, content);
  }
  return dir;
}

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    severity: "high",
    rule: "EXEC-EVAL",
    description: "Dynamic code execution via eval()",
    file: "index.js",
    line: 1,
    match: 'eval("x")',
    ...overrides,
  };
}

describe("loadAllowlist", () => {
  it("returns empty entries when no files exist", () => {
    const result = loadAllowlist([join(TEST_DIR, "nonexistent.json")]);
    expect(result.entries).toHaveLength(0);
  });

  it("loads entries from a JSON array", () => {
    const p = join(TEST_DIR, "array-allowlist.json");
    writeFileSync(
      p,
      JSON.stringify([
        { rule: "EXEC-EVAL", reason: "used intentionally" },
        { rule: "NET-OUTBOUND", file: "lib/*.js" },
      ]),
    );
    const result = loadAllowlist([p]);
    expect(result.entries).toHaveLength(2);
    expect(result.entries[0]!.rule).toBe("EXEC-EVAL");
    expect(result.entries[0]!.reason).toBe("used intentionally");
    expect(result.entries[1]!.file).toBe("lib/*.js");
  });

  it("loads entries from an object with entries key", () => {
    const p = join(TEST_DIR, "obj-allowlist.json");
    writeFileSync(
      p,
      JSON.stringify({ entries: [{ rule: "CRED-SSH", file: "test/**" }] }),
    );
    const result = loadAllowlist([p]);
    expect(result.entries).toHaveLength(1);
    expect(result.entries[0]!.rule).toBe("CRED-SSH");
  });

  it("merges entries from multiple files", () => {
    const p1 = join(TEST_DIR, "merge1.json");
    const p2 = join(TEST_DIR, "merge2.json");
    writeFileSync(p1, JSON.stringify([{ rule: "EXEC-EVAL" }]));
    writeFileSync(p2, JSON.stringify([{ rule: "NET-OUTBOUND" }]));
    const result = loadAllowlist([p1, p2]);
    expect(result.entries).toHaveLength(2);
  });

  it("skips invalid JSON files gracefully", () => {
    const p = join(TEST_DIR, "bad.json");
    writeFileSync(p, "not valid json {{{");
    const result = loadAllowlist([p]);
    expect(result.entries).toHaveLength(0);
  });

  it("ignores entries without a string rule", () => {
    const p = join(TEST_DIR, "no-rule.json");
    writeFileSync(p, JSON.stringify([{ file: "x.js" }, { rule: 123 }, { rule: "OK" }]));
    const result = loadAllowlist([p]);
    expect(result.entries).toHaveLength(1);
    expect(result.entries[0]!.rule).toBe("OK");
  });
});

describe("isSuppressed", () => {
  it("suppresses by rule ID alone", () => {
    const allowlist: Allowlist = { entries: [{ rule: "EXEC-EVAL" }] };
    expect(isSuppressed(makeFinding(), allowlist)).toBe(true);
  });

  it("does not suppress when rule does not match", () => {
    const allowlist: Allowlist = { entries: [{ rule: "NET-OUTBOUND" }] };
    expect(isSuppressed(makeFinding(), allowlist)).toBe(false);
  });

  it("suppresses with wildcard rule", () => {
    const allowlist: Allowlist = { entries: [{ rule: "*" }] };
    expect(isSuppressed(makeFinding(), allowlist)).toBe(true);
    expect(isSuppressed(makeFinding({ rule: "CRED-SSH" }), allowlist)).toBe(true);
  });

  it("suppresses when rule and file pattern both match", () => {
    const allowlist: Allowlist = { entries: [{ rule: "EXEC-EVAL", file: "index.js" }] };
    expect(isSuppressed(makeFinding({ file: "index.js" }), allowlist)).toBe(true);
  });

  it("does not suppress when file pattern does not match", () => {
    const allowlist: Allowlist = { entries: [{ rule: "EXEC-EVAL", file: "lib/*.js" }] };
    expect(isSuppressed(makeFinding({ file: "index.js" }), allowlist)).toBe(false);
  });

  it("matches glob pattern with *", () => {
    const allowlist: Allowlist = { entries: [{ rule: "EXEC-EVAL", file: "lib/*.js" }] };
    expect(isSuppressed(makeFinding({ file: "lib/helper.js" }), allowlist)).toBe(true);
    expect(isSuppressed(makeFinding({ file: "lib/deep/helper.js" }), allowlist)).toBe(false);
  });

  it("matches glob pattern with **", () => {
    const allowlist: Allowlist = { entries: [{ rule: "EXEC-EVAL", file: "src/**/*.js" }] };
    expect(isSuppressed(makeFinding({ file: "src/deep/nested/file.js" }), allowlist)).toBe(true);
    expect(isSuppressed(makeFinding({ file: "lib/file.js" }), allowlist)).toBe(false);
  });
});

describe("applyAllowlist", () => {
  it("returns all findings when allowlist is empty", () => {
    const findings = [makeFinding(), makeFinding({ rule: "CRED-SSH" })];
    const [kept, suppressed] = applyAllowlist(findings, { entries: [] });
    expect(kept).toHaveLength(2);
    expect(suppressed).toBe(0);
  });

  it("filters matching findings and counts them", () => {
    const findings = [
      makeFinding({ rule: "EXEC-EVAL" }),
      makeFinding({ rule: "CRED-SSH" }),
      makeFinding({ rule: "NET-OUTBOUND" }),
    ];
    const allowlist: Allowlist = { entries: [{ rule: "EXEC-EVAL" }, { rule: "NET-OUTBOUND" }] };
    const [kept, suppressed] = applyAllowlist(findings, allowlist);
    expect(kept).toHaveLength(1);
    expect(kept[0]!.rule).toBe("CRED-SSH");
    expect(suppressed).toBe(2);
  });
});

describe("scanner integration with allowlist", () => {
  it("suppresses findings via skill-local allowlist file", async () => {
    const dir = createSkill("allowlisted-skill", {
      "index.js": 'eval("test"); console.log("hello");',
      ".clawhub-allowlist.json": JSON.stringify([
        { rule: "EXEC-EVAL", reason: "intentional eval for templating" },
      ]),
    });
    const report = await scanSkill(dir);
    expect(report.findings.some((f) => f.rule === "EXEC-EVAL")).toBe(false);
    expect(report.suppressed).toBe(1);
  });

  it("suppresses findings via explicit allowlist option", async () => {
    const dir = createSkill("explicit-allowlist", {
      "index.js": 'eval("test"); Object.keys(process.env);',
    });
    const allowlistPath = join(TEST_DIR, "explicit.json");
    writeFileSync(
      allowlistPath,
      JSON.stringify([
        { rule: "EXEC-EVAL" },
        { rule: "CRED-ENV-HARVEST" },
      ]),
    );
    const allowlist = loadAllowlist([allowlistPath]);
    const report = await scanSkill(dir, { allowlist });
    expect(report.findings.some((f) => f.rule === "EXEC-EVAL")).toBe(false);
    expect(report.findings.some((f) => f.rule === "CRED-ENV-HARVEST")).toBe(false);
    expect(report.suppressed).toBe(2);
  });

  it("does not suppress unmatched rules", async () => {
    const dir = createSkill("partial-allowlist", {
      "index.js": 'eval("test");',
      ".clawhub-allowlist.json": JSON.stringify([{ rule: "CRED-SSH" }]),
    });
    const report = await scanSkill(dir);
    expect(report.findings.some((f) => f.rule === "EXEC-EVAL")).toBe(true);
    expect(report.suppressed).toBe(0);
  });

  it("file-scoped allowlist only suppresses matching files", async () => {
    const dir = createSkill("file-scoped-allowlist", {
      "lib/helper.js": 'eval("helper");',
      "index.js": 'eval("main");',
      ".clawhub-allowlist.json": JSON.stringify([
        { rule: "EXEC-EVAL", file: "lib/*.js" },
      ]),
    });
    const report = await scanSkill(dir);
    // lib/helper.js eval should be suppressed, index.js eval should remain
    const evalFindings = report.findings.filter((f) => f.rule === "EXEC-EVAL");
    expect(evalFindings).toHaveLength(1);
    expect(evalFindings[0]!.file).toBe("index.js");
    expect(report.suppressed).toBe(1);
  });

  it("score is recalculated after suppression", async () => {
    const dir = createSkill("score-after-suppress", {
      "index.js": 'eval("test");',
    });
    const reportNoAllow = await scanSkill(dir, { allowlist: { entries: [] } });
    const reportAllow = await scanSkill(dir, {
      allowlist: { entries: [{ rule: "EXEC-EVAL" }] },
    });
    expect(reportAllow.score).toBeGreaterThan(reportNoAllow.score);
    expect(reportAllow.score).toBe(100);
  });
});
