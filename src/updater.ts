/**
 * Threat intelligence feed updater for clawhub-scanner.
 *
 * Fetches an IoC feed (JSON) from a remote URL or local file and caches it at
 * ~/.config/clawhub-scanner/threat-feed.json. The scanner merges the cached
 * feed with its built-in indicators at scan time.
 */

import fs from "node:fs";
import path from "node:path";
import https from "node:https";
import http from "node:http";
import os from "node:os";
import { URL } from "node:url";

// ---------------------------------------------------------------------------
// Feed schema
// ---------------------------------------------------------------------------

export interface ThreatFeed {
  /** Unix timestamp (seconds) when the feed was fetched */
  fetchedAt: number;
  /** Feed format version */
  version?: string;
  /** Source URL or file path */
  source: string;
  /** Additional C2 IP patterns (regex strings, same format as indicators.ts) */
  c2IpPatterns?: string[];
  /** Additional C2 domain patterns (regex strings) */
  c2Domains?: string[];
  /** Additional known-malicious SHA-256 hashes */
  maliciousHashes?: string[];
  /** Additional known-malicious npm package names */
  maliciousPackages?: string[];
}

// ---------------------------------------------------------------------------
// Cache path
// ---------------------------------------------------------------------------

export function getDefaultCacheDir(): string {
  return path.join(os.homedir(), ".config", "clawhub-scanner");
}

export function getDefaultCachePath(): string {
  return path.join(getDefaultCacheDir(), "threat-feed.json");
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

export function loadCachedFeed(cachePath?: string): ThreatFeed | null {
  const p = cachePath ?? getDefaultCachePath();
  try {
    const raw = fs.readFileSync(p, "utf-8");
    const parsed = JSON.parse(raw) as ThreatFeed;
    if (typeof parsed.fetchedAt !== "number") return null;
    return parsed;
  } catch {
    return null;
  }
}

export function saveCachedFeed(feed: ThreatFeed, cachePath?: string): void {
  const p = cachePath ?? getDefaultCachePath();
  fs.mkdirSync(path.dirname(p), { recursive: true });
  const tmp = p + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(feed, null, 2));
  fs.renameSync(tmp, p);
}

// ---------------------------------------------------------------------------
// Remote fetch
// ---------------------------------------------------------------------------

/**
 * Fetch content from an HTTP(S) URL. Returns the body as a string.
 * Rejects on non-2xx status or network error.
 */
export function fetchUrl(url: string, timeoutMs = 15_000): Promise<string> {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const lib = parsed.protocol === "https:" ? https : http;

    const req = lib.get(url, { timeout: timeoutMs }, (res) => {
      if (res.statusCode == null || res.statusCode < 200 || res.statusCode >= 300) {
        res.resume();
        reject(new Error(`HTTP ${res.statusCode ?? "unknown"} for ${url}`));
        return;
      }
      const chunks: Buffer[] = [];
      res.on("data", (chunk: Buffer) => chunks.push(chunk));
      res.on("end", () => resolve(Buffer.concat(chunks).toString("utf-8")));
      res.on("error", reject);
    });
    req.on("timeout", () => {
      req.destroy();
      reject(new Error(`Timeout fetching ${url}`));
    });
    req.on("error", reject);
  });
}

/**
 * Read content from a local file path.
 */
export function readLocalFile(filePath: string): string {
  return fs.readFileSync(filePath, "utf-8");
}

// ---------------------------------------------------------------------------
// Feed validation
// ---------------------------------------------------------------------------

export function validateFeed(raw: unknown): ThreatFeed {
  if (typeof raw !== "object" || raw === null) {
    throw new Error("Feed must be a JSON object");
  }
  const feed = raw as Record<string, unknown>;

  // Validate array fields if present
  for (const key of ["c2IpPatterns", "c2Domains", "maliciousHashes", "maliciousPackages"] as const) {
    if (key in feed && !Array.isArray(feed[key])) {
      throw new Error(`Feed field "${key}" must be an array`);
    }
    if (Array.isArray(feed[key])) {
      for (const item of feed[key] as unknown[]) {
        if (typeof item !== "string") {
          throw new Error(`Feed field "${key}" must be an array of strings`);
        }
      }
    }
  }

  return {
    fetchedAt: Math.floor(Date.now() / 1000),
    version: typeof feed.version === "string" ? feed.version : undefined,
    source: typeof feed.source === "string" ? feed.source : "unknown",
    c2IpPatterns: Array.isArray(feed.c2IpPatterns) ? (feed.c2IpPatterns as string[]) : [],
    c2Domains: Array.isArray(feed.c2Domains) ? (feed.c2Domains as string[]) : [],
    maliciousHashes: Array.isArray(feed.maliciousHashes) ? (feed.maliciousHashes as string[]) : [],
    maliciousPackages: Array.isArray(feed.maliciousPackages) ? (feed.maliciousPackages as string[]) : [],
  };
}

// ---------------------------------------------------------------------------
// Update command
// ---------------------------------------------------------------------------

/** Default upstream threat-feed URL */
export const DEFAULT_FEED_URL =
  "https://raw.githubusercontent.com/elvatis/clawhub-scanner/main/threat-feed.json";

export interface UpdateOptions {
  /** Remote URL or local file path to fetch feed from. Defaults to DEFAULT_FEED_URL. */
  source?: string;
  /** Path to cache file. Defaults to ~/.config/clawhub-scanner/threat-feed.json. */
  cachePath?: string;
  /** Timeout in ms for remote fetch. Default: 15000. */
  timeoutMs?: number;
}

export interface UpdateResult {
  success: boolean;
  source: string;
  cachePath: string;
  feed?: ThreatFeed;
  error?: string;
  /** Stats from the fetched feed */
  stats?: {
    c2IpPatterns: number;
    c2Domains: number;
    maliciousHashes: number;
    maliciousPackages: number;
  };
}

export async function updateThreatFeed(options: UpdateOptions = {}): Promise<UpdateResult> {
  const source = options.source ?? DEFAULT_FEED_URL;
  const cachePath = options.cachePath ?? getDefaultCachePath();
  const timeoutMs = options.timeoutMs ?? 15_000;

  let rawContent: string;

  // Determine if source is a local file or a URL
  const isLocalFile = !source.startsWith("http://") && !source.startsWith("https://");

  try {
    if (isLocalFile) {
      rawContent = readLocalFile(source);
    } else {
      rawContent = await fetchUrl(source, timeoutMs);
    }
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    return { success: false, source, cachePath, error: `Failed to fetch feed: ${msg}` };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(rawContent);
  } catch {
    return { success: false, source, cachePath, error: "Feed is not valid JSON" };
  }

  let feed: ThreatFeed;
  try {
    feed = validateFeed(parsed);
    feed.source = source;
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    return { success: false, source, cachePath, error: `Invalid feed format: ${msg}` };
  }

  try {
    saveCachedFeed(feed, cachePath);
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    return { success: false, source, cachePath, error: `Failed to save feed: ${msg}` };
  }

  return {
    success: true,
    source,
    cachePath,
    feed,
    stats: {
      c2IpPatterns: feed.c2IpPatterns?.length ?? 0,
      c2Domains: feed.c2Domains?.length ?? 0,
      maliciousHashes: feed.maliciousHashes?.length ?? 0,
      maliciousPackages: feed.maliciousPackages?.length ?? 0,
    },
  };
}

// ---------------------------------------------------------------------------
// Feed merge: extend built-in indicators with cached feed data
// ---------------------------------------------------------------------------

export interface MergedIndicators {
  c2IpPatterns: string[];
  c2Domains: string[];
  maliciousHashes: Set<string>;
  maliciousPackages: Set<string>;
}

/**
 * Merge built-in indicators with a cached threat feed.
 * Deduplicates hashes and packages.
 */
export function mergeIndicators(
  builtin: {
    c2IpPatterns: string[];
    c2Domains: string[];
    maliciousHashes: Set<string>;
    maliciousPackages: Set<string>;
  },
  feed: ThreatFeed | null,
): MergedIndicators {
  if (!feed) {
    return {
      c2IpPatterns: [...builtin.c2IpPatterns],
      c2Domains: [...builtin.c2Domains],
      maliciousHashes: new Set(builtin.maliciousHashes),
      maliciousPackages: new Set(builtin.maliciousPackages),
    };
  }

  // Merge and deduplicate array fields
  const c2IpPatterns = [...new Set([...builtin.c2IpPatterns, ...(feed.c2IpPatterns ?? [])])];
  const c2Domains = [...new Set([...builtin.c2Domains, ...(feed.c2Domains ?? [])])];
  const maliciousHashes = new Set([...builtin.maliciousHashes, ...(feed.maliciousHashes ?? [])]);
  const maliciousPackages = new Set([...builtin.maliciousPackages, ...(feed.maliciousPackages ?? [])]);

  return { c2IpPatterns, c2Domains, maliciousHashes, maliciousPackages };
}
