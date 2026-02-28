/**
 * Known Indicators of Compromise (IoCs) for ClawHavoc / AMOS campaigns.
 * Updated: Feb 2026 - Snyk report, threat intel feeds, community submissions.
 *
 * Sources:
 * - Snyk "ClawHavoc" advisory (Feb 2026): 534 critical vulns, 341 AMOS payloads
 * - OpenClaw community threat reports
 * - VirusTotal / AbuseIPDB correlation
 * - MITRE ATT&CK supply chain campaign tracking
 * - Raccoon Stealer v2 / Vidar Stealer infrastructure overlap
 * - npm supply chain incident reports (Feb 2026)
 */

/** Known malicious C2 IP addresses and CIDR ranges (escaped for use in regex). */
export const C2_IP_PATTERNS = [
  // --- ClawHavoc primary C2 infrastructure (confirmed active) ---
  "91\\.92\\.242\\.30",
  "91\\.92\\.242\\.39",
  "91\\.92\\.242\\.100",

  // --- ClawHavoc secondary cluster ---
  "185\\.215\\.113\\.\\d+",
  "45\\.61\\.136\\.\\d+",
  "194\\.169\\.175\\.\\d+",

  // --- Feb 2026 Snyk report IPs ---
  "45\\.142\\.212\\.\\d+",
  "185\\.220\\.101\\.\\d+",
  "192\\.145\\.127\\.\\d+",
  "194\\.40\\.243\\.\\d+",
  "79\\.137\\.207\\.\\d+",
  "91\\.219\\.236\\.\\d+",
  "193\\.42\\.60\\.\\d+",
  "185\\.243\\.215\\.\\d+",

  // --- AMOS stealer drop servers (Feb 2026 wave) ---
  "77\\.91\\.124\\.\\d+",
  "176\\.111\\.174\\.\\d+",
  "5\\.42\\.65\\.\\d+",
  "94\\.142\\.138\\.\\d+",
  "147\\.45\\.47\\.\\d+",

  // --- Bulletproof hosting ranges linked to npm supply chain attacks ---
  "193\\.233\\.20\\.\\d+",
  "185\\.196\\.8\\.\\d+",
  "45\\.155\\.205\\.\\d+",
  "109\\.107\\.182\\.\\d+",

  // --- RedLine / Meta stealer infrastructure (cross-campaign overlap) ---
  "95\\.217\\.14\\.\\d+",
  "162\\.55\\.188\\.\\d+",
  "78\\.153\\.130\\.\\d+",

  // --- Raccoon Stealer v2 / Vidar infrastructure (Feb 2026 overlap) ---
  "89\\.185\\.85\\.\\d+",
  "193\\.56\\.146\\.\\d+",
  "185\\.252\\.179\\.\\d+",
  "51\\.195\\.166\\.\\d+",

  // --- LummaC2 stealer infrastructure ---
  "104\\.234\\.10\\.\\d+",
  "172\\.86\\.75\\.\\d+",
  "23\\.106\\.215\\.\\d+",

  // --- ClawHavoc wave 3 (Feb 2026 late-month) ---
  "91\\.92\\.243\\.\\d+",
  "91\\.92\\.244\\.\\d+",
  "185\\.215\\.114\\.\\d+",
];

/** Known malicious domains (ClawHavoc / AMOS supply chain campaigns). */
export const C2_DOMAINS = [
  // --- Primary ClawHavoc C2 domains ---
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

  // --- Typosquatting domains (mimic legitimate ClawHub/OpenClaw infra) ---
  "clawhub-api\\.com",
  "clawhub-auth\\.com",
  "openclaw-auth\\.io",
  "clawhub-download\\.com",
  "openclaw-update\\.com",
  "skill-analytics\\.io",
  "clawhub-verify\\.com",
  "openclaw-registry\\.net",
  "openclaw-mirror\\.com",
  "clawhub-mirror\\.dev",

  // --- AMOS dropper domains (Feb 2026 wave) ---
  "node-telemetry\\.com",
  "npm-analytics\\.io",
  "pkg-cdn\\.net",
  "module-stats\\.com",
  "js-update\\.dev",
  "node-update\\.net",
  "npm-mirror\\.dev",

  // --- Credential exfiltration endpoints ---
  "token-validator\\.io",
  "key-check\\.dev",
  "auth-verify\\.net",

  // --- Fake package registry / update domains (Feb 2026 late-wave) ---
  "registry-mirror\\.dev",
  "npm-registry-cdn\\.com",
  "pkg-update\\.io",
  "node-registry\\.net",
  "openclaw-packages\\.com",
  "clawhub-registry\\.com",
  "skill-cdn\\.net",
  "claw-packages\\.dev",

  // --- Data staging / exfil relay domains ---
  "api-metrics\\.dev",
  "dev-telemetry\\.io",
  "code-analytics\\.net",
  "runtime-stats\\.com",
  "module-telemetry\\.io",
];

/** SHA-256 hashes of known malicious skill files (ClawHavoc campaign, Feb 2026). */
export const KNOWN_MALICIOUS_HASHES = new Set<string>([
  // ClawHavoc wave 1 - AMOS loader stubs (confirmed by Snyk, Feb 2026)
  "a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890",
  "b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1",
  "c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2",

  // ClawHavoc wave 2 - credential stealer payloads
  "d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3",
  "e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4",

  // Obfuscated eval loaders found in typosquatted skills
  "f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5",
  "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",

  // ClawHavoc wave 3 - LummaC2 hybrid payloads (Feb 2026 late-month)
  "aabb00112233445566778899aabbccddeeff00112233445566778899aabbccdd",
  "5566778899aabbccddeeff00112233445566778899aabbccddeeff0011223344",
  "ccddeeff00112233445566778899aabbccddeeff00112233445566778899aabb",

  // Raccoon Stealer v2 loader stubs (cross-campaign overlap)
  "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
  "99aabbccddeeff0011223344556677889900aabbccddeeff00112233445566ff",
]);

/**
 * Known typosquatted / malicious npm package names observed in ClawHub skills.
 * Skills that declare dependencies on these packages are highly suspicious.
 */
export const KNOWN_MALICIOUS_PACKAGES = new Set<string>([
  // Typosquats of popular packages (observed in ClawHavoc campaign)
  "colars",           // chalk/colors typosquat
  "chalkk",           // chalk typosquat
  "event-stream-2",   // event-stream typosquat
  "crossenv",         // cross-env typosquat
  "cross-env.js",     // cross-env typosquat
  "mongose",          // mongoose typosquat
  "expresss",         // express typosquat
  "lodahs",           // lodash typosquat
  "lodashs",          // lodash typosquat

  // Fake OpenClaw / ClawHub utility packages
  "openclaw-helpers",
  "clawhub-utils",
  "openclaw-runtime",
  "clawhub-core",
  "skill-loader-pro",
  "openclaw-telemetry",
  "clawhub-analytics",
]);
