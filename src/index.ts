#!/usr/bin/env node
import { writeFileSync } from "node:fs";
import { Command } from "commander";
import { runScan, scanSkill, getDefaultSkillPaths } from "./scanner.js";
import { loadAllowlist } from "./allowlist.js";
import { printReport, formatJson } from "./reporter.js";
import type { Allowlist } from "./types.js";

const program = new Command();

program
  .name("clawhub-scanner")
  .description("Scan ClawHub skills for malware, credential theft, and security risks")
  .version("0.1.0");

program
  .command("scan")
  .description("Scan installed skills for security issues")
  .option("-s, --skill <path>", "Scan a specific skill directory")
  .option("-j, --json", "Output results as JSON")
  .option("-v, --verbose", "Show all findings including low severity")
  .option("-q, --quiet", "Only output if issues found")
  .option("-o, --output <file>", "Write report to a file instead of (or in addition to) stdout")
  .option("-a, --allowlist <path>", "Path to allowlist JSON file for suppressing false positives")
  .action(async (opts) => {
    let result;
    let allowlist: Allowlist | undefined;

    if (opts.allowlist) {
      allowlist = loadAllowlist([opts.allowlist]);
    }

    if (opts.skill) {
      const report = await scanSkill(opts.skill, { allowlist });
      result = {
        timestamp: new Date().toISOString(),
        skillsScanned: 1,
        totalFindings: report.findings.length,
        critical: report.findings.filter((f) => f.severity === "critical").length,
        high: report.findings.filter((f) => f.severity === "high").length,
        medium: report.findings.filter((f) => f.severity === "medium").length,
        low: report.findings.filter((f) => f.severity === "low").length,
        info: report.findings.filter((f) => f.severity === "info").length,
        skills: [report],
        suppressed: report.suppressed,
      };
    } else {
      result = await runScan({ allowlist });
    }

    if (opts.quiet && result.totalFindings === 0) {
      process.exit(0);
    }

    if (!opts.verbose) {
      // Shallow-copy skills/findings to avoid mutating the original result.
      result = {
        ...result,
        skills: result.skills.map((s) => ({
          ...s,
          findings: s.findings.filter((f) => f.severity !== "low" && f.severity !== "info"),
        })),
      };
      result.low = 0;
      result.info = 0;
      result.totalFindings = result.skills.reduce((sum, s) => sum + s.findings.length, 0);
    }

    const output = opts.json ? formatJson(result) : null;

    if (opts.output) {
      const content = opts.json ? formatJson(result) : formatJson(result); // always JSON to file
      writeFileSync(opts.output, content, "utf-8");
      if (!opts.json) {
        // Still print human report to stdout when --output is used without --json
        printReport(result);
      } else {
        console.log(output);
      }
    } else if (opts.json) {
      console.log(output);
    } else {
      printReport(result);
    }

    // Exit code: 2 for critical, 1 for high, 0 otherwise
    if (result.critical > 0) process.exit(2);
    if (result.high > 0) process.exit(1);
    process.exit(0);
  });

program
  .command("paths")
  .description("Show default skill directories being scanned")
  .action(() => {
    const paths = getDefaultSkillPaths();
    console.log(`Found ${paths.length} skill directories:\n`);
    for (const p of paths) {
      console.log(`  ${p}`);
    }
  });

program.parse();
