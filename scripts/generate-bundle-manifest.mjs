#!/usr/bin/env node
/**
 * Record the SHA-256 of every client asset a build produced.
 *
 * The result is the reference the integrity monitor compares a live deployment
 * against. It is generated in CI from the same build that produces the signed
 * image, so "what CI built" and "what is being served" become comparable.
 *
 *   node scripts/generate-bundle-manifest.mjs [--next-dir .next] [--out bundle-manifest.json]
 */
import { createHash } from "node:crypto"
import { readdir, readFile, writeFile } from "node:fs/promises"
import { join, posix, relative, sep } from "node:path"
import process from "node:process"

const args = process.argv.slice(2)
const argValue = (flag, fallback) => {
  const i = args.indexOf(flag)
  return i !== -1 && args[i + 1] ? args[i + 1] : fallback
}

const nextDir = argValue("--next-dir", ".next")
const outFile = argValue("--out", "bundle-manifest.json")
const staticDir = join(nextDir, "static")

// Anything the browser will parse. CSS is included because attribute selectors
// can exfiltrate data, so a swapped stylesheet is not merely cosmetic.
const TRACKED = /\.(?:js|mjs|css)$/

async function* walk(dir) {
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name)
    if (entry.isDirectory()) {
      yield* walk(full)
    } else if (entry.isFile() && TRACKED.test(entry.name)) {
      yield full
    }
  }
}

const assets = {}

for await (const file of walk(staticDir)) {
  // Public URL is always POSIX-separated regardless of the build host.
  const urlPath = `/_next/static/${relative(staticDir, file).split(sep).join(posix.sep)}`
  assets[urlPath] = `sha256-${createHash("sha256").update(await readFile(file)).digest("base64")}`
}

const sorted = Object.fromEntries(Object.keys(assets).sort().map((k) => [k, assets[k]]))

const manifest = {
  sha: process.env.BUILD_SHA || "development",
  buildId: (await readFile(join(nextDir, "BUILD_ID"), "utf8").catch(() => "")).trim() || null,
  assetCount: Object.keys(sorted).length,
  assets: sorted,
}

await writeFile(outFile, `${JSON.stringify(manifest, null, 2)}\n`)

console.warn(`Wrote ${outFile}: ${manifest.assetCount} assets for build ${manifest.sha}`)

if (manifest.assetCount === 0) {
  console.error(`No assets found under ${staticDir}. Did the build run?`)
  process.exit(1)
}
