#!/usr/bin/env node

import { writeFileSync } from "node:fs";
import { resolve } from "node:path";

import { getCookies } from "@steipete/sweet-cookie";
import type { GetCookiesOptions, BrowserName } from "@steipete/sweet-cookie";
import { program } from "commander";

import { formatNetscapeCookieJar } from "./netscape.js";

program
  .name("crul")
  .description("Extract browser cookies and write a Netscape-format cookie jar file for curl/wget.")
  .version("0.1.1")
  .requiredOption("--url <url>", "URL to extract cookies for (required)")
  .option("--origins <urls...>", "additional origins to include (e.g. SSO/OAuth domains)")
  .option("--names <names...>", "filter to specific cookie names")
  .option("--browsers <browsers...>", "browser backends to try: chrome, edge, firefox, safari")
  .option("--profile <profile>", "alias for --chrome-profile")
  .option("--chrome-profile <profile>", "Chrome profile name, directory, or Cookies DB path")
  .option("--edge-profile <profile>", "Edge profile name, directory, or Cookies DB path")
  .option("--firefox-profile <profile>", "Firefox profile name or directory path")
  .option("--safari-cookies-file <path>", "override path to Safari Cookies.binarycookies")
  .option("--chromium-browser <browser>", "macOS Chromium target: chrome, brave, arc, chromium")
  .option("--include-expired", "include expired cookies", false)
  .option("--timeout-ms <ms>", "timeout for OS helper calls (ms)", parseInt)
  .option("--mode <mode>", "merge (default) or first", "merge")
  .option("--inline-cookies-file <path>", "read inline cookie payload from file")
  .option("--inline-cookies-json <json>", "inline cookie payload as JSON string")
  .option("--inline-cookies-base64 <base64>", "inline cookie payload as base64-encoded JSON")
  .option("--debug", "emit extra provider warnings to stderr", false)
  .option("--output <path>", "output file path (omit to write to stdout)");

program.parse();

const opts = program.opts();

const getCookiesOptions: GetCookiesOptions = {
  url: opts.url,
  origins: opts.origins,
  names: opts.names,
  browsers: opts.browsers as BrowserName[] | undefined,
  profile: opts.profile,
  chromeProfile: opts.chromeProfile,
  edgeProfile: opts.edgeProfile,
  firefoxProfile: opts.firefoxProfile,
  safariCookiesFile: opts.safariCookiesFile,
  chromiumBrowser: opts.chromiumBrowser as "chrome" | "brave" | "arc" | "chromium" | undefined,
  includeExpired: opts.includeExpired,
  timeoutMs: opts.timeoutMs,
  mode: opts.mode as "merge" | "first",
  inlineCookiesFile: opts.inlineCookiesFile,
  inlineCookiesJson: opts.inlineCookiesJson,
  inlineCookiesBase64: opts.inlineCookiesBase64,
  debug: opts.debug,
};

// Strip undefined values so sweet-cookie uses its own defaults
for (const key of Object.keys(getCookiesOptions) as (keyof GetCookiesOptions)[]) {
  if (getCookiesOptions[key] === undefined) {
    delete getCookiesOptions[key];
  }
}

try {
  const { cookies, warnings } = await getCookies(getCookiesOptions);

  if (opts.debug || warnings.length > 0) {
    for (const warning of warnings) {
      console.error(`[warn] ${warning}`);
    }
  }

  const output = formatNetscapeCookieJar(cookies);

  if (opts.output) {
    const outPath = resolve(opts.output);
    writeFileSync(outPath, output, { mode: 0o600 });
    console.error(`Wrote ${cookies.length} cookie(s) to ${outPath}`);
  } else {
    process.stdout.write(output);
  }
} catch (err) {
  console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
}
