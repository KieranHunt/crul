import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, test, expect, afterEach, afterAll, beforeAll, vi } from "vitest";

import {
  createFirefoxCookieDb,
  cleanupTmpDir,
  runCrul,
  parseNetscapeCookieJar,
  type TestCookie,
} from "./helpers";

// ---------------------------------------------------------------------------
// Freeze time so all expiry constants are deterministic.
//
// NOTE: vi.setSystemTime only affects Date.now / new Date() in this Vitest process.
// The CLI runs in a child Node process with real time, so expiry offsets must
// be large enough that the child's "is expired?" check agrees with ours.
// ---------------------------------------------------------------------------
const NOW = new Date("2025-06-01T00:00:00Z");
const NOW_SECONDS = Math.floor(NOW.getTime() / 1000);

beforeAll(() => {
  vi.setSystemTime(NOW);
});

afterAll(() => {
  vi.setSystemTime(vi.getRealSystemTime()); // restore real time
});

// 10 years ahead / 10 years behind — unambiguously future/past for both
// the frozen test process and the real-time child process.
const FUTURE_EXPIRY = NOW_SECONDS + 86400 * 365 * 10;
const PAST_EXPIRY = NOW_SECONDS - 86400 * 365 * 10;

const dirs: string[] = [];

function setupDb(cookies: TestCookie[]): string {
  const dir = createFirefoxCookieDb(cookies);
  dirs.push(dir);
  return dir;
}

afterEach(() => {
  for (const dir of dirs) {
    cleanupTmpDir(dir);
  }
  dirs.length = 0;
});

// -------------------------------------------------------------------------
// Helpers to build common CLI args
// -------------------------------------------------------------------------

function firefoxArgs(
  profileDir: string,
  url = "https://example.com",
  extra: string[] = [],
): string[] {
  return ["--url", url, "--browsers", "firefox", "--firefox-profile", profileDir, ...extra];
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

describe("crul integration tests", () => {
  test("extracts a single cookie and outputs valid Netscape format", async () => {
    const dir = setupDb([
      {
        name: "session",
        value: "abc123",
        host: ".example.com",
        expiry: FUTURE_EXPIRY,
      },
    ]);

    const result = await runCrul(firefoxArgs(dir));

    expect(result.exitCode).toBe(0);
    expect(parseNetscapeCookieJar(result.stdout)).toMatchInlineSnapshot(`
      [
        {
          "domain": "example.com",
          "expires": "2064096000",
          "flag": "FALSE",
          "name": "session",
          "path": "/",
          "secure": "FALSE",
          "value": "abc123",
        },
      ]
    `);
  });

  test("extracts multiple cookies for the same domain", async () => {
    const dir = setupDb([
      {
        name: "a",
        value: "1",
        host: ".example.com",
        expiry: FUTURE_EXPIRY,
      },
      {
        name: "b",
        value: "2",
        host: ".example.com",
        expiry: FUTURE_EXPIRY,
      },
      {
        name: "c",
        value: "3",
        host: ".example.com",
        expiry: FUTURE_EXPIRY,
      },
    ]);

    const result = await runCrul(firefoxArgs(dir));

    expect(result.exitCode).toBe(0);
    expect(parseNetscapeCookieJar(result.stdout)).toMatchInlineSnapshot(`
      [
        {
          "domain": "example.com",
          "expires": "2064096000",
          "flag": "FALSE",
          "name": "a",
          "path": "/",
          "secure": "FALSE",
          "value": "1",
        },
        {
          "domain": "example.com",
          "expires": "2064096000",
          "flag": "FALSE",
          "name": "b",
          "path": "/",
          "secure": "FALSE",
          "value": "2",
        },
        {
          "domain": "example.com",
          "expires": "2064096000",
          "flag": "FALSE",
          "name": "c",
          "path": "/",
          "secure": "FALSE",
          "value": "3",
        },
      ]
    `);
  });

  test("httpOnly cookies get the #HttpOnly_ domain prefix", async () => {
    const dir = setupDb([
      {
        name: "secret",
        value: "hidden",
        host: ".example.com",
        isHttpOnly: 1,
        expiry: FUTURE_EXPIRY,
      },
    ]);

    const result = await runCrul(firefoxArgs(dir));

    expect(result.exitCode).toBe(0);
    expect(parseNetscapeCookieJar(result.stdout)).toMatchInlineSnapshot(`
      [
        {
          "domain": "#HttpOnly_example.com",
          "expires": "2064096000",
          "flag": "FALSE",
          "name": "secret",
          "path": "/",
          "secure": "FALSE",
          "value": "hidden",
        },
      ]
    `);
  });

  test("secure flag is mapped correctly", async () => {
    const dir = setupDb([
      {
        name: "secure_cookie",
        value: "yes",
        host: ".example.com",
        isSecure: 1,
        expiry: FUTURE_EXPIRY,
      },
      {
        name: "insecure_cookie",
        value: "no",
        host: ".example.com",
        isSecure: 0,
        expiry: FUTURE_EXPIRY,
      },
    ]);

    const result = await runCrul(firefoxArgs(dir));

    expect(result.exitCode).toBe(0);
    expect(parseNetscapeCookieJar(result.stdout)).toMatchInlineSnapshot(`
      [
        {
          "domain": "example.com",
          "expires": "2064096000",
          "flag": "FALSE",
          "name": "secure_cookie",
          "path": "/",
          "secure": "TRUE",
          "value": "yes",
        },
        {
          "domain": "example.com",
          "expires": "2064096000",
          "flag": "FALSE",
          "name": "insecure_cookie",
          "path": "/",
          "secure": "FALSE",
          "value": "no",
        },
      ]
    `);
  });

  test("domain cookies from Firefox are normalized (leading dot stripped)", async () => {
    const dir = setupDb([
      {
        name: "domain_cookie",
        value: "val",
        host: ".example.com",
        expiry: FUTURE_EXPIRY,
      },
      {
        name: "host_cookie",
        value: "val",
        host: "example.com",
        expiry: FUTURE_EXPIRY,
      },
    ]);

    const result = await runCrul(firefoxArgs(dir));

    expect(result.exitCode).toBe(0);
    expect(parseNetscapeCookieJar(result.stdout)).toMatchInlineSnapshot(`
      [
        {
          "domain": "example.com",
          "expires": "2064096000",
          "flag": "FALSE",
          "name": "domain_cookie",
          "path": "/",
          "secure": "FALSE",
          "value": "val",
        },
        {
          "domain": "example.com",
          "expires": "2064096000",
          "flag": "FALSE",
          "name": "host_cookie",
          "path": "/",
          "secure": "FALSE",
          "value": "val",
        },
      ]
    `);
  });

  test("--names filters to only specified cookie names", async () => {
    const dir = setupDb([
      {
        name: "keep",
        value: "yes",
        host: ".example.com",
        expiry: FUTURE_EXPIRY,
      },
      {
        name: "drop",
        value: "no",
        host: ".example.com",
        expiry: FUTURE_EXPIRY,
      },
    ]);

    const result = await runCrul(firefoxArgs(dir, "https://example.com", ["--names", "keep"]));

    expect(result.exitCode).toBe(0);
    expect(parseNetscapeCookieJar(result.stdout)).toMatchInlineSnapshot(`
      [
        {
          "domain": "example.com",
          "expires": "2064096000",
          "flag": "FALSE",
          "name": "keep",
          "path": "/",
          "secure": "FALSE",
          "value": "yes",
        },
      ]
    `);
  });

  test("expired cookies are excluded by default", async () => {
    const dir = setupDb([
      {
        name: "fresh",
        value: "yes",
        host: ".example.com",
        expiry: FUTURE_EXPIRY,
      },
      {
        name: "stale",
        value: "no",
        host: ".example.com",
        expiry: PAST_EXPIRY,
      },
    ]);

    const result = await runCrul(firefoxArgs(dir));

    expect(result.exitCode).toBe(0);
    expect(parseNetscapeCookieJar(result.stdout)).toMatchInlineSnapshot(`
      [
        {
          "domain": "example.com",
          "expires": "2064096000",
          "flag": "FALSE",
          "name": "fresh",
          "path": "/",
          "secure": "FALSE",
          "value": "yes",
        },
      ]
    `);
  });

  test("--include-expired includes expired cookies", async () => {
    const dir = setupDb([
      {
        name: "fresh",
        value: "yes",
        host: ".example.com",
        expiry: FUTURE_EXPIRY,
      },
      {
        name: "stale",
        value: "no",
        host: ".example.com",
        expiry: PAST_EXPIRY,
      },
    ]);

    const result = await runCrul(firefoxArgs(dir, "https://example.com", ["--include-expired"]));

    expect(result.exitCode).toBe(0);
    expect(parseNetscapeCookieJar(result.stdout)).toMatchInlineSnapshot(`
      [
        {
          "domain": "example.com",
          "expires": "2064096000",
          "flag": "FALSE",
          "name": "fresh",
          "path": "/",
          "secure": "FALSE",
          "value": "yes",
        },
        {
          "domain": "example.com",
          "expires": "1433376000",
          "flag": "FALSE",
          "name": "stale",
          "path": "/",
          "secure": "FALSE",
          "value": "no",
        },
      ]
    `);
  });

  test("--output writes cookie jar to a file", async () => {
    const dir = setupDb([
      {
        name: "token",
        value: "xyz",
        host: ".example.com",
        expiry: FUTURE_EXPIRY,
      },
    ]);

    const outPath = join(dir, "cookies.txt");
    const result = await runCrul(firefoxArgs(dir, "https://example.com", ["--output", outPath]));

    expect(result.exitCode).toBe(0);
    expect(result.stdout).toBe("");
    expect(existsSync(outPath)).toBe(true);

    const content = readFileSync(outPath, "utf-8");
    expect(parseNetscapeCookieJar(content)).toMatchInlineSnapshot(`
      [
        {
          "domain": "example.com",
          "expires": "2064096000",
          "flag": "FALSE",
          "name": "token",
          "path": "/",
          "secure": "FALSE",
          "value": "xyz",
        },
      ]
    `);
  });

  test("missing --url exits with non-zero code", async () => {
    const result = await runCrul(["--browsers", "firefox"]);

    expect(result.exitCode).not.toBe(0);
    expect(result.stderr).toContain("--url");
  });

  test("no matching cookies produces header-only output", async () => {
    const dir = setupDb([
      {
        name: "other",
        value: "val",
        host: ".other-domain.com",
        expiry: FUTURE_EXPIRY,
      },
    ]);

    const result = await runCrul(firefoxArgs(dir));

    expect(result.exitCode).toBe(0);
    expect(parseNetscapeCookieJar(result.stdout)).toMatchInlineSnapshot(`[]`);
  });

  test("cookie path is preserved", async () => {
    const dir = setupDb([
      {
        name: "scoped",
        value: "val",
        host: ".example.com",
        path: "/api/v1",
        expiry: FUTURE_EXPIRY,
      },
    ]);

    const result = await runCrul(firefoxArgs(dir));

    expect(result.exitCode).toBe(0);
    expect(parseNetscapeCookieJar(result.stdout)).toMatchInlineSnapshot(`
      [
        {
          "domain": "example.com",
          "expires": "2064096000",
          "flag": "FALSE",
          "name": "scoped",
          "path": "/api/v1",
          "secure": "FALSE",
          "value": "val",
        },
      ]
    `);
  });

  test("session cookies (expiry=0) output 0 as expiry", async () => {
    const dir = setupDb([
      {
        name: "sess",
        value: "val",
        host: ".example.com",
        expiry: 0,
      },
    ]);

    const result = await runCrul(firefoxArgs(dir, "https://example.com", ["--include-expired"]));

    expect(result.exitCode).toBe(0);
    expect(parseNetscapeCookieJar(result.stdout)).toMatchInlineSnapshot(`
      [
        {
          "domain": "example.com",
          "expires": "0",
          "flag": "FALSE",
          "name": "sess",
          "path": "/",
          "secure": "FALSE",
          "value": "val",
        },
      ]
    `);
  });
});
