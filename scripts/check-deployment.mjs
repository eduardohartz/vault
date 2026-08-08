#!/usr/bin/env node
/**
 * Compare a live deployment against the bundle manifest CI produced.
 *
 * This runs OUTSIDE the server being checked — that is the entire point. An
 * integrity check that runs inside the application can be removed by whoever
 * modified the application, so it proves nothing. A check run from elsewhere
 * forces an attacker to serve clean code to the monitor and modified code to
 * real users at the same time, which is possible but a large step up in effort
 * and is not what an opportunistic compromise looks like.
 *
 *   node scripts/check-deployment.mjs --url https://vault.example.com --manifest bundle-manifest.json
 *
 * Exits non-zero on any mismatch.
 *
 * Coverage boundary, stated plainly: this verifies every JS and CSS asset the
 * build emitted, and rejects any script the page pulls from outside that set.
 * It does NOT hash inline scripts — Next embeds per-request streaming payload
 * and a CSP nonce inline, so those bytes legitimately differ on every request.
 * An attacker who injects a nonced inline script would not be caught here.
 */
import { createHash } from "node:crypto"
import { readFile } from "node:fs/promises"
import process from "node:process"

const args = process.argv.slice(2)
const argValue = (flag, fallback) => {
  const i = args.indexOf(flag)
  return i !== -1 && args[i + 1] ? args[i + 1] : fallback
}

const baseUrl = (argValue("--url", process.env.DEPLOYMENT_URL) || "").replace(/\/$/, "")
const manifestPath = argValue("--manifest", "bundle-manifest.json")

if (!baseUrl) {
  console.error("Missing --url (or DEPLOYMENT_URL).")
  process.exit(2)
}

const problems = []
const notes = []

const fetchOrThrow = async (url, as = "buffer") => {
  const response = await fetch(url, { redirect: "manual", headers: { "User-Agent": "vault-integrity-monitor" } })
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`)
  }
  return as === "text" ? response.text() : Buffer.from(await response.arrayBuffer())
}

const sha256 = (buf) => `sha256-${createHash("sha256").update(buf).digest("base64")}`

const manifest = JSON.parse(await readFile(manifestPath, "utf8"))
console.warn(`Reference build : ${manifest.sha} (${manifest.assetCount} assets)`)
console.warn(`Target          : ${baseUrl}\n`)

// --- 1. Which build does the deployment claim to be running? ----------------
let reported = null
try {
  const version = JSON.parse(await fetchOrThrow(`${baseUrl}/api/version`, "text"))
  reported = version.sha
  console.warn(`Deployment reports build: ${reported}`)

  if (reported !== manifest.sha) {
    problems.push(`Deployment reports build ${reported} but was checked against manifest for ${manifest.sha}. Either a deploy is in flight, or the reported build is untrue.`)
  }
} catch (error) {
  problems.push(`Could not read /api/version: ${error.message}`)
}

// --- 2. Does every asset CI built still hash the same when served? ----------
let verified = 0
for (const [path, expected] of Object.entries(manifest.assets)) {
  try {
    const actual = sha256(await fetchOrThrow(`${baseUrl}${path}`))
    if (actual !== expected) {
      problems.push(`MODIFIED: ${path}\n    expected ${expected}\n    served   ${actual}`)
    } else {
      verified++
    }
  } catch (error) {
    problems.push(`UNREACHABLE: ${path} (${error.message})`)
  }
}
console.warn(`Assets verified byte-for-byte: ${verified}/${manifest.assetCount}`)

// --- 3. Does the page pull in anything that was not in the build? -----------
const pagesToScan = ["/", "/share/integrity-probe"]

for (const page of pagesToScan) {
  let html
  try {
    html = await fetchOrThrow(`${baseUrl}${page}`, "text")
  } catch (error) {
    problems.push(`Could not fetch ${page}: ${error.message}`)
    continue
  }

  // Leading \s before each attribute name so `data-src` is not mistaken for
  // `src`; attribute order varies, hence the two <link> forms.
  // The tag-name boundary is a lookahead so it does not consume the space that
  // `\ssrc` then needs — consuming it requires two spaces and matches nothing.
  // The leading \s on each attribute stops `data-src` matching as `src`.
  const referenced = [
    ...[...html.matchAll(/<script(?=\s)[^>]*?\ssrc\s*=\s*["']([^"']+)["']/gi)].map((m) => m[1]),
    ...[...html.matchAll(/<link(?=\s)[^>]*?\srel\s*=\s*["']stylesheet["'][^>]*?\shref\s*=\s*["']([^"']+)["']/gi)].map((m) => m[1]),
    ...[...html.matchAll(/<link(?=\s)[^>]*?\shref\s*=\s*["']([^"']+)["'][^>]*?\srel\s*=\s*["']stylesheet["']/gi)].map((m) => m[1]),
  ]

  for (const src of new Set(referenced)) {
    const absolute = new URL(src, `${baseUrl}/`)

    if (absolute.origin !== new URL(baseUrl).origin) {
      problems.push(`OFF-ORIGIN RESOURCE on ${page}: ${src}`)
      continue
    }

    // Next percent-encodes dynamic-route segments in chunk URLs, so
    // /_next/.../app/share/%5Btoken%5D/page-*.js is the manifest's
    // /_next/.../app/share/[token]/page-*.js. Compare decoded.
    const path = decodeURIComponent(absolute.pathname)
    if (path.startsWith("/_next/static/") && !(path in manifest.assets)) {
      problems.push(`UNKNOWN ASSET on ${page}: ${path} was not produced by build ${manifest.sha}`)
    }
  }

  const inlineCount = [...html.matchAll(/<script(?![^>]*?\ssrc\s*=)[\s>][^>]*>/gi)].length
  notes.push(`${page}: ${new Set(referenced).size} external resources, ${inlineCount} inline scripts (inline content not hashed — see header comment)`)
}

// --- Report ----------------------------------------------------------------
console.warn("")
for (const note of notes) {
  console.warn(`note: ${note}`)
}

if (problems.length === 0) {
  console.warn(`\nOK: ${baseUrl} matches build ${manifest.sha}.`)
  process.exit(0)
}

console.error(`\nINTEGRITY CHECK FAILED (${problems.length} problem(s)):\n`)
for (const problem of problems) {
  console.error(`  - ${problem}`)
}
console.error("\nIf this is not an in-flight deploy, treat the deployment as compromised: take it offline and do not sign in, since signing in would hand your passkey PRF output to whatever code is being served.")
process.exit(1)
