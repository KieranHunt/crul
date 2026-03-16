import Database from "better-sqlite3";
import { execFile } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface TestCookie {
  name: string;
  value: string;
  host: string; // e.g. ".example.com" or "example.com"
  path?: string; // defaults to "/"
  expiry?: number; // Unix seconds, 0 = session
  isSecure?: number; // 0 or 1
  isHttpOnly?: number; // 0 or 1
  sameSite?: number; // 0 = None, 1 = Lax, 2 = Strict
}

export interface ParsedCookie {
  domain: string;
  flag: string; // "TRUE" or "FALSE"
  path: string;
  secure: string; // "TRUE" or "FALSE"
  expires: string;
  name: string;
  value: string;
}

export interface RunResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

// ---------------------------------------------------------------------------
// Firefox cookie DB fixture
// ---------------------------------------------------------------------------

/**
 * Create a temporary directory containing a Firefox-format `cookies.sqlite`
 * database populated with the given cookies.
 *
 * Returns the path to the temp directory (suitable for `--firefox-profile`).
 * The caller is responsible for cleanup (see {@link cleanupTmpDir}).
 */
export function createFirefoxCookieDb(cookies: TestCookie[]): string {
  const dir = mkdtempSync(join(tmpdir(), "crul-test-"));
  const dbPath = join(dir, "cookies.sqlite");
  const db = new Database(dbPath);

  db.exec(`
    CREATE TABLE moz_cookies (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      name        TEXT    NOT NULL,
      value       TEXT    NOT NULL,
      host        TEXT    NOT NULL,
      path        TEXT    NOT NULL DEFAULT '/',
      expiry      INTEGER NOT NULL DEFAULT 0,
      isSecure    INTEGER NOT NULL DEFAULT 0,
      isHttpOnly  INTEGER NOT NULL DEFAULT 0,
      sameSite    INTEGER NOT NULL DEFAULT 0
    );
  `);

  const insert = db.prepare(`
    INSERT INTO moz_cookies (name, value, host, path, expiry, isSecure, isHttpOnly, sameSite)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?);
  `);

  for (const c of cookies) {
    insert.run(
      c.name,
      c.value,
      c.host,
      c.path ?? "/",
      c.expiry ?? 0,
      c.isSecure ?? 0,
      c.isHttpOnly ?? 0,
      c.sameSite ?? 0,
    );
  }

  db.close();
  return dir;
}

/**
 * Remove a temp directory created by {@link createFirefoxCookieDb}.
 */
export function cleanupTmpDir(dir: string): void {
  rmSync(dir, { recursive: true, force: true });
}

// ---------------------------------------------------------------------------
// CLI runner
// ---------------------------------------------------------------------------

const __dirname = dirname(fileURLToPath(import.meta.url));
const CLI_PATH = resolve(__dirname, "..", "dist", "cli.js");

/**
 * Spawn the compiled CLI as a subprocess and collect its output.
 */
export async function runCrul(args: string[]): Promise<RunResult> {
  return new Promise((resolve) => {
    execFile("node", [CLI_PATH, ...args], {
      env: {
        ...process.env,
        // Prevent sweet-cookie from picking up real browser cookies
        HOME: "/nonexistent",
        APPDATA: "/nonexistent",
      },
    }, (error, stdout, stderr) => {
      resolve({
        stdout: stdout ?? "",
        stderr: stderr ?? "",
        exitCode: error?.code != null ? (typeof error.code === "number" ? error.code : 1) : 0,
      });
    });
  });
}

// ---------------------------------------------------------------------------
// Netscape cookie jar parser
// ---------------------------------------------------------------------------

/**
 * Parse a Netscape-format cookie jar string into structured objects.
 * Skips comment lines (starting with `#` that aren't `#HttpOnly_` prefixed)
 * and blank lines.
 */
export function parseNetscapeCookieJar(text: string): ParsedCookie[] {
  const cookies: ParsedCookie[] = [];

  for (const line of text.split("\n")) {
    const trimmed = line.trim();
    if (trimmed === "") continue;

    // Regular comments start with # but #HttpOnly_ prefixed lines are cookie data
    if (trimmed.startsWith("#") && !trimmed.startsWith("#HttpOnly_")) continue;

    const parts = trimmed.split("\t");
    if (parts.length < 7) continue;

    cookies.push({
      domain: parts[0]!,
      flag: parts[1]!,
      path: parts[2]!,
      secure: parts[3]!,
      expires: parts[4]!,
      name: parts[5]!,
      value: parts[6]!,
    });
  }

  return cookies;
}
