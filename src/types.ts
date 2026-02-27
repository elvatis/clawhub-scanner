export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Finding {
  severity: Severity;
  rule: string;
  description: string;
  file: string;
  line?: number;
  match?: string;
}

export interface SkillReport {
  name: string;
  path: string;
  findings: Finding[];
  scannedFiles: number;
  score: number; // 0-100, 100 = clean
}

export interface ScanResult {
  timestamp: string;
  skillsScanned: number;
  totalFindings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  skills: SkillReport[];
}

export interface DetectionRule {
  id: string;
  severity: Severity;
  description: string;
  pattern: RegExp;
  fileFilter?: RegExp;
  /** If true, the pattern is tested against the full file content (not line-by-line). Required for patterns that span multiple lines. */
  multiline?: boolean;
}
