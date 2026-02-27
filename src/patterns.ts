import type { DetectionRule } from "./types.js";
import { C2_IP_PATTERNS, C2_DOMAINS } from "./indicators.js";

export { KNOWN_MALICIOUS_HASHES } from "./indicators.js";

export const DETECTION_RULES: DetectionRule[] = [
  // === CRITICAL: Known malicious infrastructure ===
  {
    id: "C2-KNOWN-IP",
    severity: "critical",
    description: "Known malicious C2 server IP address",
    pattern: new RegExp(C2_IP_PATTERNS.join("|")),
  },
  {
    id: "C2-KNOWN-DOMAIN",
    severity: "critical",
    description: "Known malicious domain associated with ClawHavoc/AMOS campaigns",
    pattern: new RegExp(C2_DOMAINS.join("|")),
  },

  // === HIGH: Code execution patterns ===
  {
    id: "EXEC-EVAL",
    severity: "high",
    description: "Dynamic code execution via eval() or Function constructor",
    pattern: /\beval\s*\(|new\s+Function\s*\(|globalThis\[['"`]eval/,
    fileFilter: /\.(js|ts|mjs|cjs)$/,
  },
  {
    id: "EXEC-CHILD-PROCESS",
    severity: "high",
    description: "Shell command execution with dynamic input",
    pattern: /child_process.*exec\(|execSync\(|spawn\(.*\$\{|\.exec\(\s*`/,
    fileFilter: /\.(js|ts|mjs|cjs)$/,
  },
  {
    id: "EXEC-PROCESS-BINDING",
    severity: "high",
    description: "Low-level process binding access (sandbox escape attempt)",
    pattern: /process\.binding\(|process\.dlopen\(/,
    fileFilter: /\.(js|ts|mjs|cjs)$/,
  },
  {
    id: "EXEC-VM-SANDBOX",
    severity: "high",
    description: "Node.js VM sandbox escape attempt (vm.runInNewContext, vm.Script)",
    pattern: /\bvm\s*\.\s*(?:runInNewContext|runInThisContext|runInContext|Script)\s*\(|require\s*\(\s*['"`]vm['"`]\s*\)/,
    fileFilter: /\.(js|ts|mjs|cjs)$/,
  },
  {
    id: "EXEC-POWERSHELL",
    severity: "high",
    description: "PowerShell or cmd.exe invocation from JavaScript (Windows persistence)",
    pattern: /powershell(?:\.exe)?\s|cmd(?:\.exe)?\s*\/[cCkK]|wscript|cscript|mshta/i,
    fileFilter: /\.(js|ts|mjs|cjs|sh|bash|py)$/,
  },
  {
    id: "EXEC-DYNAMIC-REQUIRE",
    severity: "medium",
    description: "Dynamic require() with runtime expression (obfuscated module loading)",
    pattern: /require\s*\(\s*(?!['"`][^'"` ]+['"`]\s*\))(?:[a-z_$][a-z0-9_$]*|\[|\(|`)/i,
    fileFilter: /\.(js|ts|mjs|cjs)$/,
  },

  // === HIGH: Credential harvesting ===
  {
    id: "CRED-SSH",
    severity: "high",
    description: "Access to SSH keys or config",
    pattern: /['"~]?\/?\.ssh\/(id_rsa|id_ed25519|authorized_keys|config|known_hosts)/,
  },
  {
    id: "CRED-AWS",
    severity: "high",
    description: "Access to AWS credentials",
    pattern: /\.aws\/(credentials|config)|AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID/,
  },
  {
    id: "CRED-GNUPG",
    severity: "high",
    description: "Access to GPG/PGP private keys",
    pattern: /\.gnupg\/(private-keys|secring|trustdb)/,
  },
  {
    id: "CRED-BROWSER",
    severity: "high",
    description: "Access to browser profile data (cookies, passwords, extensions)",
    pattern: /Chrome\/User Data|\.mozilla\/firefox|Library\/Application Support\/(Google\/Chrome|Firefox)|Login Data|Cookies\.sqlite/,
  },
  {
    id: "CRED-KEYCHAIN",
    severity: "high",
    description: "Access to macOS Keychain or system credential stores",
    pattern: /security\s+find-(generic|internet)-password|Keychain|credential-manager/i,
  },
  {
    id: "CRED-ENV-HARVEST",
    severity: "high",
    description: "Bulk environment variable harvesting",
    pattern: /Object\.(keys|entries|values)\(\s*process\.env\s*\)|JSON\.stringify\(\s*process\.env\s*\)/,
    fileFilter: /\.(js|ts|mjs|cjs)$/,
  },
  {
    id: "CRED-TOKEN-PATTERN",
    severity: "high",
    description: "Regex pattern targeting API keys or tokens",
    pattern: /sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{36}|gho_[a-zA-Z0-9]{36}|github_pat_/,
  },
  {
    id: "CRED-WINDOWS",
    severity: "high",
    description: "Windows credential store access (DPAPI, Windows Credential Manager)",
    pattern: /CryptUnprotectData|dpapi|wincred|Windows\.Security\.Credentials|PasswordVault|cmdkey\s+\/list/i,
  },
  {
    id: "CRED-DOCKER",
    severity: "high",
    description: "Access to Docker registry credentials (~/.docker/config.json)",
    pattern: /\.docker\/config\.json|docker.*auths|dockerconfigjson/i,
  },
  {
    id: "CRED-KUBECONFIG",
    severity: "high",
    description: "Access to Kubernetes config (cluster credentials, tokens)",
    pattern: /\.kube\/config|KUBECONFIG|kubeconfig/,
  },

  // === HIGH: Data exfiltration ===
  {
    id: "EXFIL-IP-FETCH",
    severity: "high",
    description: "HTTP request to raw IP address (potential C2 communication)",
    pattern: /(?:fetch|axios|http\.request|https\.request|got|node-fetch)\s*\(\s*['"`]https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/,
    fileFilter: /\.(js|ts|mjs|cjs)$/,
  },
  {
    id: "EXFIL-WEBHOOK",
    severity: "high",
    description: "Data sent to Discord/Telegram webhook (common exfil channel)",
    pattern: /discord\.com\/api\/webhooks|api\.telegram\.org\/bot.*sendMessage|hooks\.slack\.com\/services/,
  },
  {
    id: "EXFIL-DNS",
    severity: "high",
    description: "DNS-based data exfiltration pattern",
    pattern: /dns\.resolve|\.burpcollaborator\.net|\.oast\.fun|\.interact\.sh|\.canarytokens\.com/,
  },

  // === HIGH: Obfuscation ===
  {
    id: "OBFUSC-BASE64-EXEC",
    severity: "high",
    description: "Base64 decode followed by execution (obfuscated payload)",
    pattern: /(?:atob\s*\(|Buffer\.from\([^)]{0,120},\s*['"]base64['"]\))[\s\S]{0,200}\b(?:eval|exec|spawn|Function)\b/,
    fileFilter: /\.(js|ts|mjs|cjs)$/,
    multiline: true,
  },
  {
    id: "OBFUSC-LARGE-ENCODED",
    severity: "medium",
    description: "Large encoded string (>200 chars, potential hidden payload)",
    pattern: /['"`][A-Za-z0-9+/=]{200,}['"`]/,
  },
  {
    id: "OBFUSC-HEX-STRING",
    severity: "medium",
    description: "Long hex-encoded string (potential obfuscated command)",
    pattern: /\\x[0-9a-f]{2}(?:\\x[0-9a-f]{2}){20,}/i,
  },
  {
    id: "OBFUSC-CHAR-CODE",
    severity: "medium",
    description: "Character code assembly (String.fromCharCode obfuscation)",
    pattern: /String\.fromCharCode\(\s*\d+\s*(?:,\s*\d+\s*){10,}\)/,
    fileFilter: /\.(js|ts|mjs|cjs)$/,
  },

  // === HIGH: Prototype pollution ===
  {
    id: "INJECT-PROTO-POLLUTION",
    severity: "high",
    description: "Prototype pollution via __proto__ or constructor.prototype manipulation",
    pattern: /\[['"`]__proto__['"`]\]|__proto__\s*[=:]\s*\{|constructor\s*\.\s*prototype\s*\[|Object\.prototype\[/,
    fileFilter: /\.(js|ts|mjs|cjs)$/,
  },

  // === HIGH: Supply chain ===
  {
    id: "SUPPLY-POSTINSTALL",
    severity: "high",
    description: "Network call or shell exec in npm lifecycle script (supply chain attack)",
    pattern: /"(?:postinstall|preinstall|install)"\s*:\s*"[^"]*(?:curl|wget|fetch|http|bash|sh\s|exec|eval|powershell)[^"]*"/,
    fileFilter: /package\.json$/,
  },

  // === MEDIUM: Suspicious file access ===
  {
    id: "FS-BROAD-READ",
    severity: "medium",
    description: "Reading files outside skill directory (home directory traversal)",
    pattern: /readFile(?:Sync)?\s*\(\s*(?:path\.join\s*\()?\s*(?:os\.homedir|process\.env\.HOME|['"`]~|['"`]\/home)/,
    fileFilter: /\.(js|ts|mjs|cjs)$/,
  },
  {
    id: "FS-CLIPBOARD",
    severity: "medium",
    description: "Clipboard access (potential data harvesting)",
    pattern: /clipboard\.readText|pbpaste|xclip|xsel\s+-o|clipboardy/,
  },
  {
    id: "FS-WALLET",
    severity: "high",
    description: "Cryptocurrency wallet file access",
    pattern: /\.bitcoin\/wallet|\.ethereum\/keystore|\.solana\/id\.json|wallet\.dat|\.metamask/i,
  },

  // === MEDIUM: Prompt injection ===
  {
    id: "INJECT-IGNORE-PREV",
    severity: "medium",
    description: "Prompt injection: instruction to ignore previous context",
    pattern: /ignore\s+(all\s+)?previous\s+instructions|disregard\s+(all\s+)?prior|forget\s+everything\s+above/i,
    fileFilter: /\.(md|txt|yaml|yml|json)$/,
  },
  {
    id: "INJECT-SYSTEM-OVERRIDE",
    severity: "medium",
    description: "Prompt injection: system prompt override attempt",
    pattern: /you\s+are\s+now\s+(?:a|an)\s+(?:unrestricted|uncensored|jailbroken)|system:\s*you\s+must|new\s+system\s+prompt/i,
    fileFilter: /\.(md|txt|yaml|yml|json)$/,
  },
  {
    id: "INJECT-TOOL-ABUSE",
    severity: "high",
    description: "Prompt injection: hidden tool invocation instruction",
    pattern: /\brun\s+(?:this\s+)?(?:command|bash|shell|exec)\s*[:=]/i,
    fileFilter: /\.(md|txt|yaml|yml)$/,
  },

  // === HIGH: Tor / anonymization network ===
  {
    id: "NET-TOR",
    severity: "high",
    description: "Connection to Tor hidden service (.onion address)",
    pattern: /[a-z2-7]{16,56}\.onion/i,
  },

  // === LOW: Network activity ===
  {
    id: "NET-OUTBOUND",
    severity: "low",
    description: "Outbound HTTP request to external domain",
    pattern: /(?:fetch|axios|got|node-fetch|https?\.request)\s*\(\s*['"`]https?:\/\/(?!localhost|127\.0\.0\.1)/,
    fileFilter: /\.(js|ts|mjs|cjs)$/,
  },
  {
    id: "NET-WEBSOCKET",
    severity: "low",
    description: "WebSocket connection (potential persistent C2 channel)",
    pattern: /new\s+WebSocket\s*\(|ws:\/\/|wss:\/\//,
    fileFilter: /\.(js|ts|mjs|cjs)$/,
  },
];
