#!/usr/bin/env node
// Fails when an installed production dependency uses a license that is not on the
// allowlist of permissive, commercial-friendly licenses. Run: npm run licenses
import { readdir, readFile } from "node:fs/promises";
import path from "node:path";

const ALLOWED = new Set([
  "MIT", "MIT-0", "ISC", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "0BSD", "BlueOak-1.0.0",
  "CC0-1.0", "CC-BY-4.0", "Unlicense", "Python-2.0", "Artistic-2.0", "BSD-3-Clause OR MIT", "(MIT OR CC0-1.0)",
  "MIT OR Apache-2.0", "Apache-2.0 OR MIT", "(MIT OR Apache-2.0)", "(Apache-2.0 OR MIT)",
]);
// Packages reviewed manually (license field missing or non-SPDX but permissive).
// Each entry is a deliberate, documented decision (see docs/licensing.md).
const REVIEWED = new Map([
  ["@img/sharp-libvips-darwin-arm64", "LGPL-3.0: optional image dependency of Next.js (web UI only, dynamically linked, unmodified)."],
  ["@img/sharp-libvips-darwin-x64", "LGPL-3.0: as above."],
  ["@img/sharp-libvips-linux-x64", "LGPL-3.0: as above."],
  ["@img/sharp-libvips-linux-arm64", "LGPL-3.0: as above."],
  ["@img/sharp-libvips-linuxmusl-x64", "LGPL-3.0: as above."],
  ["@img/sharp-libvips-linuxmusl-arm64", "LGPL-3.0: as above."],
  ["@img/sharp-wasm32", "Apache-2.0 AND LGPL-3.0: as above."],
  ["lightningcss", "MPL-2.0: build-time CSS tool for the web UI (Tailwind); not shipped in the CLI."],
  ["lightningcss-darwin-arm64", "MPL-2.0: as above."],
  ["lightningcss-darwin-x64", "MPL-2.0: as above."],
  ["lightningcss-linux-x64-gnu", "MPL-2.0: as above."],
  ["lightningcss-linux-x64-musl", "MPL-2.0: as above."],
  ["lightningcss-linux-arm64-gnu", "MPL-2.0: as above."],
]);

const root = path.resolve(new URL("..", import.meta.url).pathname);
const problems = [];
const seen = new Map();
const reviewed = new Set();

async function scan(dir) {
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const e of entries) {
    if (!e.isDirectory() && !e.isSymbolicLink()) continue;
    if (e.name.startsWith("@")) {
      await scan(path.join(dir, e.name));
      continue;
    }
    if (e.name.startsWith(".")) continue;
    const pkgDir = path.join(dir, e.name);
    try {
      const pkg = JSON.parse(await readFile(path.join(pkgDir, "package.json"), "utf8"));
      if (pkg.name?.startsWith("@mungard/") || pkg.name === "mungard") continue;
      const license = typeof pkg.license === "string" ? pkg.license : pkg.license?.type ?? (Array.isArray(pkg.licenses) ? pkg.licenses.map((l) => l.type).join(" OR ") : undefined);
      seen.set(`${pkg.name}@${pkg.version}`, license);
      if (!license || !ALLOWED.has(license)) {
        if (REVIEWED.has(pkg.name)) reviewed.add(`${pkg.name} (${license}): ${REVIEWED.get(pkg.name)}`);
        else problems.push(`${pkg.name}@${pkg.version}: ${license ?? "UNKNOWN"}`);
      }
    } catch {
      // not a package directory
    }
    await scan(path.join(pkgDir, "node_modules"));
  }
}

await scan(path.join(root, "node_modules"));
const counts = {};
for (const l of seen.values()) counts[l ?? "UNKNOWN"] = (counts[l ?? "UNKNOWN"] ?? 0) + 1;
console.log(`Checked ${seen.size} packages:`, counts);
if (reviewed.size) console.warn(`\nWARNING: weak-copyleft licenses accepted after review:\n  ${[...reviewed].sort().join("\n  ")}`);
if (problems.length) {
  console.error(`\nLicenses needing review (${problems.length}):\n  ${problems.sort().join("\n  ")}`);
  process.exitCode = 1;
} else {
  console.log(reviewed.size ? "All other dependency licenses are on the permissive allowlist." : "All dependency licenses are on the permissive allowlist.");
}
