import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import http from "node:http";
import type { AddressInfo } from "node:net";

import {
  loadCachedFeed,
  saveCachedFeed,
  validateFeed,
  mergeIndicators,
  updateThreatFeed,
  getDefaultCachePath,
  getDefaultCacheDir,
  DEFAULT_FEED_URL,
  type ThreatFeed,
} from "../src/updater.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function tmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "clawhub-update-test-"));
}

function sampleFeed(): ThreatFeed {
  return {
    fetchedAt: 1700000000,
    version: "1.0",
    source: "https://example.com/feed.json",
    c2IpPatterns: ["1\\.2\\.3\\.4"],
    c2Domains: ["evil\\.example\\.com"],
    maliciousHashes: ["abc123def456abc123def456abc123def456abc123def456abc123def456abc123"],
    maliciousPackages: ["bad-package"],
  };
}

/** Start a minimal HTTP server that serves the given body with the given status code. */
function startMockServer(
  handler: (req: http.IncomingMessage, res: http.ServerResponse) => void
): Promise<{ server: http.Server; url: string }> {
  return new Promise((resolve, reject) => {
    const server = http.createServer(handler);
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address() as AddressInfo;
      resolve({ server, url: `http://127.0.0.1:${addr.port}` });
    });
    server.on("error", reject);
  });
}

function stopServer(server: http.Server): Promise<void> {
  return new Promise((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())));
}

// ---------------------------------------------------------------------------
// getDefaultCachePath / getDefaultCacheDir
// ---------------------------------------------------------------------------

describe("getDefaultCachePath", () => {
  it("returns a path under ~/.config/clawhub-scanner", () => {
    const p = getDefaultCachePath();
    expect(p).toContain("clawhub-scanner");
    expect(p.endsWith("threat-feed.json")).toBe(true);
  });

  it("getDefaultCacheDir is the parent of the default cache path", () => {
    const cacheDir = getDefaultCacheDir();
    const cachePath = getDefaultCachePath();
    expect(cachePath).toBe(path.join(cacheDir, "threat-feed.json"));
  });
});

// ---------------------------------------------------------------------------
// loadCachedFeed / saveCachedFeed
// ---------------------------------------------------------------------------

describe("loadCachedFeed", () => {
  let dir: string;

  beforeEach(() => {
    dir = tmpDir();
  });

  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("returns null when cache file does not exist", () => {
    expect(loadCachedFeed(path.join(dir, "nonexistent.json"))).toBeNull();
  });

  it("returns null for invalid JSON", () => {
    const p = path.join(dir, "bad.json");
    fs.writeFileSync(p, "{not valid");
    expect(loadCachedFeed(p)).toBeNull();
  });

  it("returns null when fetchedAt is missing", () => {
    const p = path.join(dir, "nots.json");
    fs.writeFileSync(p, JSON.stringify({ source: "x" }));
    expect(loadCachedFeed(p)).toBeNull();
  });

  it("loads a valid cached feed", () => {
    const p = path.join(dir, "feed.json");
    const feed = sampleFeed();
    fs.writeFileSync(p, JSON.stringify(feed));
    const loaded = loadCachedFeed(p);
    expect(loaded).not.toBeNull();
    expect(loaded!.fetchedAt).toBe(1700000000);
    expect(loaded!.source).toBe("https://example.com/feed.json");
    expect(loaded!.c2IpPatterns).toEqual(["1\\.2\\.3\\.4"]);
  });
});

describe("saveCachedFeed", () => {
  let dir: string;

  beforeEach(() => {
    dir = tmpDir();
  });

  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("saves feed to given path", () => {
    const p = path.join(dir, "feed.json");
    saveCachedFeed(sampleFeed(), p);
    const raw = fs.readFileSync(p, "utf-8");
    const parsed = JSON.parse(raw);
    expect(parsed.fetchedAt).toBe(1700000000);
  });

  it("creates parent directories if they do not exist", () => {
    const p = path.join(dir, "nested", "deep", "feed.json");
    saveCachedFeed(sampleFeed(), p);
    expect(fs.existsSync(p)).toBe(true);
  });

  it("writes valid JSON", () => {
    const p = path.join(dir, "feed.json");
    saveCachedFeed(sampleFeed(), p);
    expect(() => JSON.parse(fs.readFileSync(p, "utf-8"))).not.toThrow();
  });

  it("does not leave a .tmp file after write", () => {
    const p = path.join(dir, "feed.json");
    saveCachedFeed(sampleFeed(), p);
    expect(fs.existsSync(p + ".tmp")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// validateFeed
// ---------------------------------------------------------------------------

describe("validateFeed", () => {
  it("accepts a complete valid feed", () => {
    const raw = { ...sampleFeed() };
    const feed = validateFeed(raw);
    expect(feed.c2IpPatterns).toEqual(["1\\.2\\.3\\.4"]);
    expect(feed.maliciousHashes).toHaveLength(1);
  });

  it("throws for non-object input", () => {
    expect(() => validateFeed("not an object")).toThrow("JSON object");
    expect(() => validateFeed(null)).toThrow("JSON object");
    expect(() => validateFeed(42)).toThrow("JSON object");
  });

  it("throws when c2IpPatterns is not an array", () => {
    expect(() => validateFeed({ c2IpPatterns: "not-array" })).toThrow("c2IpPatterns");
  });

  it("throws when c2Domains contains a non-string", () => {
    expect(() => validateFeed({ c2Domains: [42] })).toThrow("c2Domains");
  });

  it("accepts empty feed (all fields optional)", () => {
    const feed = validateFeed({});
    expect(feed.c2IpPatterns).toEqual([]);
    expect(feed.c2Domains).toEqual([]);
    expect(feed.maliciousHashes).toEqual([]);
    expect(feed.maliciousPackages).toEqual([]);
  });

  it("stamps fetchedAt as current time", () => {
    const before = Math.floor(Date.now() / 1000) - 1;
    const feed = validateFeed({});
    const after = Math.floor(Date.now() / 1000) + 1;
    expect(feed.fetchedAt).toBeGreaterThanOrEqual(before);
    expect(feed.fetchedAt).toBeLessThanOrEqual(after);
  });

  it("sets source to 'unknown' when missing", () => {
    const feed = validateFeed({});
    expect(feed.source).toBe("unknown");
  });

  it("preserves version field", () => {
    const feed = validateFeed({ version: "2.1" });
    expect(feed.version).toBe("2.1");
  });
});

// ---------------------------------------------------------------------------
// mergeIndicators
// ---------------------------------------------------------------------------

describe("mergeIndicators", () => {
  const builtin = {
    c2IpPatterns: ["1\\.1\\.1\\.1"],
    c2Domains: ["evil\\.com"],
    maliciousHashes: new Set(["aaaa"]),
    maliciousPackages: new Set(["bad-pkg"]),
  };

  it("returns builtin copy when feed is null", () => {
    const merged = mergeIndicators(builtin, null);
    expect(merged.c2IpPatterns).toEqual(["1\\.1\\.1\\.1"]);
    expect(merged.c2Domains).toEqual(["evil\\.com"]);
    expect(merged.maliciousHashes).toEqual(new Set(["aaaa"]));
    expect(merged.maliciousPackages).toEqual(new Set(["bad-pkg"]));
  });

  it("merged result is a copy (does not mutate builtin)", () => {
    const merged = mergeIndicators(builtin, null);
    merged.c2IpPatterns.push("extra");
    expect(builtin.c2IpPatterns).toHaveLength(1);
  });

  it("merges feed data with builtin indicators", () => {
    const feed: ThreatFeed = {
      fetchedAt: 1,
      source: "test",
      c2IpPatterns: ["2\\.2\\.2\\.2"],
      c2Domains: ["new\\.evil\\.com"],
      maliciousHashes: ["bbbb"],
      maliciousPackages: ["new-bad-pkg"],
    };
    const merged = mergeIndicators(builtin, feed);
    expect(merged.c2IpPatterns).toContain("1\\.1\\.1\\.1");
    expect(merged.c2IpPatterns).toContain("2\\.2\\.2\\.2");
    expect(merged.c2Domains).toContain("evil\\.com");
    expect(merged.c2Domains).toContain("new\\.evil\\.com");
    expect(merged.maliciousHashes.has("aaaa")).toBe(true);
    expect(merged.maliciousHashes.has("bbbb")).toBe(true);
    expect(merged.maliciousPackages.has("bad-pkg")).toBe(true);
    expect(merged.maliciousPackages.has("new-bad-pkg")).toBe(true);
  });

  it("deduplicates overlapping indicators", () => {
    const feed: ThreatFeed = {
      fetchedAt: 1,
      source: "test",
      c2IpPatterns: ["1\\.1\\.1\\.1"], // same as builtin
      c2Domains: ["evil\\.com"],          // same as builtin
      maliciousHashes: ["aaaa"],          // same as builtin
      maliciousPackages: ["bad-pkg"],     // same as builtin
    };
    const merged = mergeIndicators(builtin, feed);
    expect(merged.c2IpPatterns).toHaveLength(1);
    expect(merged.c2Domains).toHaveLength(1);
    expect(merged.maliciousHashes.size).toBe(1);
    expect(merged.maliciousPackages.size).toBe(1);
  });

  it("handles empty feed gracefully", () => {
    const feed: ThreatFeed = {
      fetchedAt: 1,
      source: "test",
      c2IpPatterns: [],
      c2Domains: [],
      maliciousHashes: [],
      maliciousPackages: [],
    };
    const merged = mergeIndicators(builtin, feed);
    expect(merged.c2IpPatterns).toEqual(["1\\.1\\.1\\.1"]);
    expect(merged.maliciousHashes.size).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// updateThreatFeed - local file
// ---------------------------------------------------------------------------

describe("updateThreatFeed - local file", () => {
  let dir: string;

  beforeEach(() => {
    dir = tmpDir();
  });

  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("fetches from a local file and writes cache", async () => {
    const feedPath = path.join(dir, "feed.json");
    const feedData = {
      c2IpPatterns: ["5\\.5\\.5\\.5"],
      c2Domains: ["test\\.evil"],
      maliciousHashes: [],
      maliciousPackages: ["suspicious-pkg"],
    };
    fs.writeFileSync(feedPath, JSON.stringify(feedData));
    const cachePath = path.join(dir, "cache.json");

    const result = await updateThreatFeed({ source: feedPath, cachePath });

    expect(result.success).toBe(true);
    expect(result.cachePath).toBe(cachePath);
    expect(result.stats?.c2IpPatterns).toBe(1);
    expect(result.stats?.maliciousPackages).toBe(1);
    expect(fs.existsSync(cachePath)).toBe(true);
  });

  it("returns error when local file does not exist", async () => {
    const result = await updateThreatFeed({
      source: path.join(dir, "missing.json"),
      cachePath: path.join(dir, "cache.json"),
    });

    expect(result.success).toBe(false);
    expect(result.error).toMatch(/Failed to fetch feed/);
  });

  it("returns error when local file has invalid JSON", async () => {
    const feedPath = path.join(dir, "bad.json");
    fs.writeFileSync(feedPath, "{not valid");
    const result = await updateThreatFeed({
      source: feedPath,
      cachePath: path.join(dir, "cache.json"),
    });

    expect(result.success).toBe(false);
    expect(result.error).toMatch(/not valid JSON/);
  });

  it("returns error when local feed fails validation", async () => {
    const feedPath = path.join(dir, "invalid.json");
    fs.writeFileSync(feedPath, JSON.stringify({ c2IpPatterns: "not-array" }));
    const result = await updateThreatFeed({
      source: feedPath,
      cachePath: path.join(dir, "cache.json"),
    });

    expect(result.success).toBe(false);
    expect(result.error).toMatch(/Invalid feed format/);
  });

  it("includes correct stats in result", async () => {
    const feedPath = path.join(dir, "feed.json");
    fs.writeFileSync(feedPath, JSON.stringify({
      c2IpPatterns: ["a", "b", "c"],
      c2Domains: ["x"],
      maliciousHashes: ["hash1", "hash2"],
      maliciousPackages: [],
    }));
    const result = await updateThreatFeed({
      source: feedPath,
      cachePath: path.join(dir, "cache.json"),
    });

    expect(result.success).toBe(true);
    expect(result.stats).toEqual({
      c2IpPatterns: 3,
      c2Domains: 1,
      maliciousHashes: 2,
      maliciousPackages: 0,
    });
  });
});

// ---------------------------------------------------------------------------
// updateThreatFeed - remote URL (mock HTTP server)
// ---------------------------------------------------------------------------

describe("updateThreatFeed - remote URL", () => {
  let dir: string;
  let server: http.Server | undefined;
  let baseUrl: string;

  beforeEach(() => {
    dir = tmpDir();
    server = undefined;
  });

  afterEach(async () => {
    fs.rmSync(dir, { recursive: true, force: true });
    if (server) {
      try { await stopServer(server); } catch { /* already closed */ }
      server = undefined;
    }
  });

  it("fetches from a remote URL and writes cache", async () => {
    const feedData = {
      c2IpPatterns: ["9\\.9\\.9\\.9"],
      c2Domains: ["remote\\.evil"],
      maliciousHashes: ["remote-hash"],
      maliciousPackages: [],
    };

    ({ server, url: baseUrl } = await startMockServer((_req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(feedData));
    }));

    const cachePath = path.join(dir, "cache.json");
    const result = await updateThreatFeed({ source: baseUrl, cachePath });

    expect(result.success).toBe(true);
    expect(result.stats?.c2IpPatterns).toBe(1);
    expect(result.stats?.maliciousHashes).toBe(1);
    expect(fs.existsSync(cachePath)).toBe(true);
  });

  it("returns error on HTTP 404", async () => {
    ({ server, url: baseUrl } = await startMockServer((_req, res) => {
      res.writeHead(404);
      res.end("Not Found");
    }));

    const result = await updateThreatFeed({
      source: baseUrl,
      cachePath: path.join(dir, "cache.json"),
    });

    expect(result.success).toBe(false);
    expect(result.error).toMatch(/HTTP 404/);
  });

  it("returns error on HTTP 500", async () => {
    ({ server, url: baseUrl } = await startMockServer((_req, res) => {
      res.writeHead(500);
      res.end("Internal Server Error");
    }));

    const result = await updateThreatFeed({
      source: baseUrl,
      cachePath: path.join(dir, "cache.json"),
    });

    expect(result.success).toBe(false);
    expect(result.error).toMatch(/HTTP 500/);
  });

  it("returns error when server returns invalid JSON", async () => {
    ({ server, url: baseUrl } = await startMockServer((_req, res) => {
      res.writeHead(200);
      res.end("{not valid json");
    }));

    const result = await updateThreatFeed({
      source: baseUrl,
      cachePath: path.join(dir, "cache.json"),
    });

    expect(result.success).toBe(false);
    expect(result.error).toMatch(/not valid JSON/);
  });

  it("returns error on connection refused", async () => {
    // Bind to a random free port, then close it so the port is guaranteed to be closed.
    // We track this server separately so afterEach does not try to stop it twice.
    let closedUrl = "";
    await new Promise<void>((resolve, reject) => {
      const tmpSrv = http.createServer((_req, res) => { res.end("{}"); });
      tmpSrv.listen(0, "127.0.0.1", () => {
        const addr = tmpSrv.address() as AddressInfo;
        closedUrl = `http://127.0.0.1:${addr.port}`;
        tmpSrv.close((err) => (err ? reject(err) : resolve()));
      });
    });

    const result = await updateThreatFeed({
      source: closedUrl,
      cachePath: path.join(dir, "cache.json"),
      timeoutMs: 2000,
    });

    expect(result.success).toBe(false);
    expect(result.error).toMatch(/Failed to fetch feed/);
  });

  it("sets the source field in the cached feed from the URL", async () => {
    const feedData = { c2IpPatterns: [] };
    ({ server, url: baseUrl } = await startMockServer((_req, res) => {
      res.writeHead(200);
      res.end(JSON.stringify(feedData));
    }));

    const cachePath = path.join(dir, "cache.json");
    const result = await updateThreatFeed({ source: baseUrl, cachePath });

    expect(result.success).toBe(true);
    const cached = loadCachedFeed(cachePath);
    expect(cached?.source).toBe(baseUrl);
  });
});

// ---------------------------------------------------------------------------
// DEFAULT_FEED_URL
// ---------------------------------------------------------------------------

describe("DEFAULT_FEED_URL", () => {
  it("is a valid HTTPS URL pointing to the elvatis repo", () => {
    expect(DEFAULT_FEED_URL).toMatch(/^https:\/\//);
    expect(DEFAULT_FEED_URL).toContain("elvatis/clawhub-scanner");
    expect(DEFAULT_FEED_URL).toContain("threat-feed.json");
  });
});
