import chalk from "chalk";
import type { ScanResult, SkillReport, Finding, Severity } from "./types.js";

const SEVERITY_COLORS: Record<Severity, (s: string) => string> = {
  critical: chalk.bgRed.white.bold,
  high: chalk.red.bold,
  medium: chalk.yellow,
  low: chalk.blue,
  info: chalk.gray,
};

const SEVERITY_ICONS: Record<Severity, string> = {
  critical: "🚨",
  high: "🔴",
  medium: "🟡",
  low: "🔵",
  info: "ℹ️",
};

function scoreColor(score: number): (s: string) => string {
  if (score >= 90) return chalk.green.bold;
  if (score >= 70) return chalk.yellow;
  if (score >= 50) return chalk.red;
  return chalk.bgRed.white.bold;
}

function printFinding(f: Finding): void {
  const icon = SEVERITY_ICONS[f.severity];
  const sev = SEVERITY_COLORS[f.severity](f.severity.toUpperCase().padEnd(8));
  const loc = f.line ? `${f.file}:${f.line}` : f.file;
  console.log(`  ${icon} ${sev} ${chalk.dim(f.rule)}`);
  console.log(`     ${f.description}`);
  console.log(`     ${chalk.dim(loc)}`);
  if (f.match) {
    console.log(`     ${chalk.dim("match:")} ${chalk.dim(f.match)}`);
  }
  console.log();
}

function printSkill(skill: SkillReport): void {
  const sc = scoreColor(skill.score);
  const badge = skill.findings.length === 0
    ? chalk.green("CLEAN")
    : skill.score < 50
      ? chalk.bgRed.white(" DANGEROUS ")
      : chalk.yellow("ISSUES");

  const suppInfo = skill.suppressed > 0 ? `  Suppressed: ${chalk.dim(String(skill.suppressed))}` : "";
  console.log(
    `${chalk.bold(skill.name)} ${badge}  Score: ${sc(String(skill.score))}  Files: ${skill.scannedFiles}${suppInfo}`
  );
  console.log(chalk.dim("-".repeat(60)));

  if (skill.findings.length === 0) {
    console.log(chalk.green("  No issues found.\n"));
    return;
  }

  for (const f of skill.findings) {
    printFinding(f);
  }
}

export function printReport(result: ScanResult): void {
  console.log();
  console.log(chalk.bold.underline("🔍 ClawHub Security Scan Report"));
  console.log(chalk.dim(`   ${result.timestamp}`));
  console.log();

  console.log(
    `Skills scanned: ${chalk.bold(String(result.skillsScanned))}  |  ` +
    `Findings: ${chalk.bold(String(result.totalFindings))}  |  ` +
    (result.critical > 0 ? chalk.bgRed.white(` ${result.critical} CRITICAL `) + "  " : "") +
    (result.high > 0 ? chalk.red(`${result.high} high`) + "  " : "") +
    (result.medium > 0 ? chalk.yellow(`${result.medium} medium`) + "  " : "") +
    (result.low > 0 ? chalk.blue(`${result.low} low`) + "  " : "") +
    (result.info > 0 ? chalk.gray(`${result.info} info`) + "  " : "") +
    (result.suppressed > 0 ? chalk.dim(`(${result.suppressed} suppressed)`) : "")
  );
  console.log();
  console.log(chalk.bold("═".repeat(60)));
  console.log();

  for (const skill of result.skills) {
    printSkill(skill);
  }

  // Summary
  console.log(chalk.bold("═".repeat(60)));
  if (result.critical > 0) {
    console.log(chalk.bgRed.white.bold("\n ⚠️  CRITICAL FINDINGS DETECTED - Immediate action required! \n"));
    console.log(chalk.red("Remove or isolate affected skills before continuing to use them."));
    console.log(chalk.red("Report malicious skills: https://clawhub.com/report\n"));
  } else if (result.high > 0) {
    console.log(chalk.red.bold("\n⚠️  High-severity findings detected. Review before use.\n"));
  } else if (result.totalFindings === 0) {
    console.log(chalk.green.bold("\n✅ All clear! No security issues found.\n"));
  } else {
    console.log(chalk.yellow("\n🔎 Some low/medium findings. Review at your convenience.\n"));
  }
}

export function formatJson(result: ScanResult): string {
  return JSON.stringify(result, null, 2);
}

/**
 * Format scan results as SARIF 2.1.0 (Static Analysis Results Interchange Format).
 *
 * SARIF is the standard consumed by GitHub Code Scanning, VS Code SARIF Viewer,
 * and most modern CI security gates. Upload the output with:
 *
 *   clawhub-scanner scan --sarif -o results.sarif
 *   gh upload-sarif --sarif-file results.sarif
 *
 * Severity mapping: critical/high → error, medium → warning, low → note, info → none
 */
export function formatSarif(result: ScanResult, toolVersion = "0.1.3"): string {
  const sarifLevel = (s: Severity): string => {
    if (s === "critical" || s === "high") return "error";
    if (s === "medium") return "warning";
    if (s === "low") return "note";
    return "none";
  };

  // Collect the unique rule set across all findings (driver.rules must be exhaustive).
  const ruleMap = new Map<string, { id: string; description: string; severity: Severity }>();
  for (const skill of result.skills) {
    for (const f of skill.findings) {
      if (!ruleMap.has(f.rule)) {
        ruleMap.set(f.rule, { id: f.rule, description: f.description, severity: f.severity });
      }
    }
  }

  const rules = [...ruleMap.values()].map((r) => ({
    id: r.id,
    // SARIF rule names must be camelCase per the spec.
    name: r.id.replace(/-([a-z])/gi, (_, c: string) => c.toUpperCase()),
    shortDescription: { text: r.description },
    helpUri: "https://github.com/elvatis/clawhub-scanner",
    properties: {
      tags: ["security", "supply-chain"],
      "security-severity": r.severity === "critical" ? "9.8"
        : r.severity === "high" ? "7.5"
        : r.severity === "medium" ? "4.0"
        : "2.0",
    },
  }));

  const sarifResults: object[] = [];
  for (const skill of result.skills) {
    for (const f of skill.findings) {
      const region: Record<string, number> = {};
      if (f.line != null) region["startLine"] = f.line;

      sarifResults.push({
        ruleId: f.rule,
        level: sarifLevel(f.severity),
        message: {
          text: f.match ? `${f.description} — match: ${f.match}` : f.description,
        },
        locations: [
          {
            physicalLocation: {
              artifactLocation: {
                uri: f.file.replace(/\\/g, "/"),
                uriBaseId: "%SRCROOT%",
              },
              ...(Object.keys(region).length > 0 ? { region } : {}),
            },
          },
        ],
      });
    }
  }

  const sarif = {
    $schema:
      "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "clawhub-scanner",
            version: toolVersion,
            informationUri: "https://github.com/elvatis/clawhub-scanner",
            rules,
          },
        },
        results: sarifResults,
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}
