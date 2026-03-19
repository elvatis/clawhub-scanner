# @elvatis_com/clawhub-scanner

Scan your installed [ClawHub](https://clawhub.com) skills for malware, credential theft, prompt injection, and security risks.

## Why?

ClawHub skills run with full agent permissions. In February 2026 alone, security researchers found:
- **534 skills** with critical vulnerabilities (Snyk)
- **341 skills** distributing the AMOS stealer ("ClawHavoc" campaign)
- **76 confirmed** malicious payloads for credential theft and data exfiltration

This scanner checks your installed skills against known malicious patterns, C2 infrastructure, and suspicious behaviors.

## Install

```bash
npm install -g @elvatis_com/clawhub-scanner
```

## Usage

```bash
# Scan all installed skills
clawhub-scanner scan

# Scan a specific skill directory (two equivalent options)
clawhub-scanner scan --skill ~/.openclaw/skills/some-skill
clawhub-scanner scan --scan-path ~/.openclaw/skills/some-skill

# JSON output for automation
clawhub-scanner scan --json

# Write report to a file (human-readable text)
clawhub-scanner scan --output report.txt

# Write JSON report to a file
clawhub-scanner scan --json --output report.json

# Include low-severity findings
clawhub-scanner scan --verbose

# Show scanned directories
clawhub-scanner paths

# Update threat intelligence feeds
clawhub-scanner update

# Update from a custom URL
clawhub-scanner update --source https://your-org.com/feeds/threat-feed.json

# Update from a local file
clawhub-scanner update --source /path/to/local-feed.json
```

### Options

| Flag | Alias | Description |
|------|-------|-------------|
| `--skill <path>` | `-s` | Scan a specific skill directory |
| `--scan-path <path>` | | Alias for `--skill` |
| `--json` | `-j` | Output results as JSON |
| `--verbose` | `-v` | Include low/info severity findings |
| `--quiet` | `-q` | Suppress output when no issues found |
| `--output <file>` | `-o` | Write report to file (text or JSON based on `--json` flag) |
| `--allowlist <path>` | `-a` | Path to allowlist JSON file |

### `update` command options

| Flag | Description |
|------|-------------|
| `--source <url-or-path>` | URL or local file path for the feed (default: GitHub raw) |
| `--cache <path>` | Override cache file location (default: `~/.config/clawhub-scanner/threat-feed.json`) |
| `--timeout <ms>` | HTTP request timeout in milliseconds (default: 15000) |

## Threat Intelligence Feed Format

The `update` command fetches a JSON file and merges it with built-in indicators. The feed is cached locally at `~/.config/clawhub-scanner/threat-feed.json`.

```json
{
  "version": "1.0",
  "c2IpPatterns": ["91\\.92\\.242\\.31", "185\\.215\\.113\\.\\d+"],
  "c2Domains": ["new-evil\\.com", "malware\\.io"],
  "maliciousHashes": ["sha256hexhash..."],
  "maliciousPackages": ["evil-npm-package"]
}
```

All fields are optional. The scanner merges these with its built-in indicators at scan time, so existing detections are never removed by an update. Pass `--offline` to `clawhub-scanner scan` to skip loading the cached feed.

## What It Detects

| Category | Severity | Examples |
|----------|----------|---------|
| **C2 Infrastructure** | Critical | Known malicious IPs (91.92.242.30), ClawHavoc domains |
| **Code Execution** | High | `eval()`, `child_process.exec()`, `process.binding()` |
| **Credential Theft** | High | SSH key access, AWS creds, browser profiles, crypto wallets |
| **Data Exfiltration** | High | Discord/Telegram webhooks, raw IP fetches, DNS tunneling |
| **Obfuscation** | High/Med | Base64+exec combos, large encoded strings, CharCode assembly |
| **Prompt Injection** | Medium | "Ignore previous instructions", system prompt overrides |
| **Network Activity** | Low | Outbound HTTP to unknown domains, WebSocket connections |

## Programmatic API

The scanner can be used as a library in your own tools, CI pipelines, or IDE plugins:

```ts
import { runScan, scanSkill } from '@elvatis_com/clawhub-scanner';
import type { ScanResult, SkillReport } from '@elvatis_com/clawhub-scanner';

// Scan all installed skills
const result: ScanResult = await runScan();
console.log(`Found ${result.critical} critical issues`);

// Scan a specific skill directory
const report: SkillReport = await scanSkill('/path/to/my-skill');
console.log(`Score: ${report.score}/100`);

// Scan with a custom allowlist
import { loadAllowlist } from '@elvatis_com/clawhub-scanner';
const allowlist = loadAllowlist(['/path/to/allowlist.json']);
const result2 = await runScan({ allowlist });

// Scan custom paths
const result3 = await runScan({ skillPaths: ['./skills/skill-a', './skills/skill-b'] });
```

Available exports:
- `runScan(options?)` — scan one or more skill directories, returns `ScanResult`
- `scanSkill(path, options?)` — scan a single skill directory, returns `SkillReport`
- `getDefaultSkillPaths()` — returns the default skill directories
- `hashFile(path)` — SHA-256 hash a file (returns `null` on error)
- `loadAllowlist(paths)` — load and merge allowlist files
- `resolveAllowlistPaths(skillPath?)` — resolve default allowlist locations
- `applyAllowlist(findings, allowlist)` — filter findings through an allowlist
- `isSuppressed(finding, allowlist)` — check if a single finding is suppressed
- `formatJson(result)` — serialize a `ScanResult` to JSON string
- `printReport(result)` — print a human-readable report to stdout
- All types: `ScanResult`, `SkillReport`, `Finding`, `Severity`, `Allowlist`, `AllowlistEntry`, `DetectionRule`

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Clean (or only low/medium findings) |
| 1 | High-severity findings detected |
| 2 | Critical findings detected |

Use in CI/scripts: `clawhub-scanner scan --quiet || echo "Security issues found!"`

## Allowlist (False-Positive Suppression)

If a rule triggers on code you've reviewed and trust, you can suppress it with an allowlist file.

Create a `.clawhub-allowlist.json` in the skill directory, or a global config at `~/.config/clawhub-scanner/allowlist.json`:

```json
[
  { "rule": "EXEC-EVAL", "reason": "eval used for intentional templating" },
  { "rule": "NET-OUTBOUND", "file": "lib/api-client.js" },
  { "rule": "CRED-ENV-HARVEST", "file": "src/**/*.ts", "reason": "reads config from env" }
]
```

Each entry has:
- `rule` (required) - the rule ID to suppress (e.g. `EXEC-EVAL`), or `*` for all rules
- `file` (optional) - glob pattern to limit suppression to specific files
- `reason` (optional) - why this is a false positive

You can also pass a custom allowlist file via CLI:

```bash
clawhub-scanner scan --allowlist ./my-allowlist.json
```

Suppressed findings are counted and shown in the report output.

## Scan Locations

By default, scans:
- `~/.openclaw/skills/` (user-installed skills)
- OpenClaw built-in skills directory

## License

MIT - [Elvatis](https://elvatis.com)
