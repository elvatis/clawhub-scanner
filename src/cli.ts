#!/usr/bin/env node
import { writeFileSync } from "node:fs";
import { Command } from "commander";
import { runScan, scanSkill, getDefaultSkillPaths } from "./scanner.js";
import { loadAllowlist } from "./allowlist.js";
import { printReport, formatJson, formatSarif } from "./reporter.js";
import { updateThreatFeed, DEFAULT_FEED_URL, getDefaultCachePath } from "./updater.js";
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
  .option("--scan-path <path>", "Alias for --skill: scan a specific skill directory")
  .option("-j, --json", "Output results as JSON")
  .option("--sarif", "Output results as SARIF 2.1.0 (for GitHub Code Scanning / CI security gates)")
  .option("-v, --verbose", "Show all findings including low severity")
  .option("-q, --quiet", "Only output if issues found")
  .option("-o, --output <file>", "Write report to a file (JSON when --json flag set, human-readable text otherwise)")
  .option("-a, --allowlist <path>", "Path to allowlist JSON file for suppressing false positives")
  .action(async (opts) => {
    let result;
    let allowlist: Allowlist | undefined;

    if (opts.allowlist) {
      allowlist = loadAllowlist([opts.allowlist]);
    }

    // --scan-path is an alias for --skill
    const skillPath: string | undefined = opts.skill ?? opts.scanPath;

    if (skillPath) {
      const report = await scanSkill(skillPath, { allowlist });
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

    if (opts.output) {
      if (opts.sarif) {
        const sarifOutput = formatSarif(result);
        writeFileSync(opts.output, sarifOutput, "utf-8");
        // Also print to stdout for piping
        console.log(sarifOutput);
      } else if (opts.json) {
        writeFileSync(opts.output, formatJson(result), "utf-8");
        // Also print JSON to stdout for piping
        console.log(formatJson(result));
      } else {
        // Capture printReport output and write to file as plain text
        const lines: string[] = [];
        const orig = console.log.bind(console);
        console.log = (...args: unknown[]) => {
          // Strip ANSI escape codes for file output
          const line = args.map(String).join(" ").replace(/\x1b\[[0-9;]*m/g, "");
          lines.push(line);
          orig(...args);
        };
        printReport(result);
        console.log = orig;
        writeFileSync(opts.output, lines.join("\n") + "\n", "utf-8");
      }
    } else if (opts.sarif) {
      console.log(formatSarif(result));
    } else if (opts.json) {
      console.log(formatJson(result));
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

program
  .command("update")
  .description("Refresh threat intelligence data from remote feed or local file")
  .option(
    "-s, --source <url-or-path>",
    `Feed source: URL or local file path (default: ${DEFAULT_FEED_URL})`
  )
  .option(
    "--cache <path>",
    `Path to local threat-feed cache (default: ${getDefaultCachePath()})`
  )
  .option("--timeout <ms>", "Request timeout in milliseconds", "15000")
  .action(async (opts) => {
    const source: string | undefined = opts.source;
    const cachePath: string | undefined = opts.cache;
    const timeoutMs = parseInt(String(opts.timeout), 10) || 15_000;

    const displaySource = source ?? DEFAULT_FEED_URL;
    console.log(`Fetching threat intelligence feed from: ${displaySource}`);

    const result = await updateThreatFeed({ source, cachePath, timeoutMs });

    if (!result.success) {
      console.error(`\n✗ Update failed: ${result.error}`);
      process.exit(1);
    }

    console.log(`✓ Feed updated successfully`);
    console.log(`  Cached at: ${result.cachePath}`);
    if (result.stats) {
      const s = result.stats;
      console.log(`  C2 IP patterns:    ${s.c2IpPatterns}`);
      console.log(`  C2 domains:        ${s.c2Domains}`);
      console.log(`  Malicious hashes:  ${s.maliciousHashes}`);
      console.log(`  Malicious pkgs:    ${s.maliciousPackages}`);
    }
    process.exit(0);
  });

program.parse();
