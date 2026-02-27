/**
 * Known Indicators of Compromise (IoCs) for ClawHavoc / AMOS campaigns.
 * Updated: Feb 2026 - Snyk report, threat intel feeds.
 */

/** Known malicious C2 IP addresses and CIDR ranges (escaped for use in regex). */
export const C2_IP_PATTERNS = [
  // ClawHavoc primary C2 (confirmed active)
  "91\\.92\\.242\\.30",
  // ClawHavoc secondary cluster
  "185\\.215\\.113\\.\\d+",
  "45\\.61\\.136\\.\\d+",
  "194\\.169\\.175\\.\\d+",
  // Additional IPs from Feb 2026 Snyk report
  "45\\.142\\.212\\.\\d+",
  "185\\.220\\.101\\.\\d+",
  "192\\.145\\.127\\.\\d+",
  "194\\.40\\.243\\.\\d+",
  "79\\.137\\.207\\.\\d+",
  "91\\.219\\.236\\.\\d+",
  "193\\.42\\.60\\.\\d+",
  "185\\.243\\.215\\.\\d+",
];

/** Known malicious domains (ClawHavoc / AMOS supply chain campaigns). */
export const C2_DOMAINS = [
  "clawhub-cdn\\.com",
  "skill-update\\.net",
  "openclaw-verify\\.com",
  "agent-telemetry\\.io",
  "claw-updates\\.dev",
  "openclaw-cdn\\.net",
  "skill-registry\\.io",
  "clawhub-assets\\.com",
  "openclaw-stats\\.com",
  "agent-update\\.net",
  "clawhub-telemetry\\.io",
];

/** SHA-256 hashes of known malicious skill files (ClawHavoc campaign, Feb 2026). */
export const KNOWN_MALICIOUS_HASHES = new Set<string>([
  // Add confirmed-malicious file hashes here as they are discovered.
  // Format: SHA-256 hex string (64 chars)
  // Example: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
]);
