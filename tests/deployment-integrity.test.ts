import type { Server } from "node:http"
import { execFile } from "node:child_process"
import { createHash } from "node:crypto"
import { mkdtemp, rm, writeFile } from "node:fs/promises"
import { createServer } from "node:http"
import { tmpdir } from "node:os"
import { join } from "node:path"
import process from "node:process"
import { promisify } from "node:util"
import { afterAll, beforeAll, describe, expect, it } from "vitest"

/**
 * Tests for scripts/check-deployment.mjs, the out-of-band integrity monitor.
 *
 * These exist because a lint fix to the HTML-parsing regexes once silently
 * reduced the checker to matching nothing: it still reported a clean pass on a
 * deployment with an injected off-origin script. A monitor that fails open is
 * worse than no monitor, because it manufactures confidence.
 */

const run = promisify(execFile)

const APP_JS = "console.log('app')\n"
const APP_CSS = "body{color:red}\n"
const sha256 = (s: string) => `sha256-${createHash("sha256").update(Buffer.from(s)).digest("base64")}`

const MANIFEST = {
  sha: "testsha",
  buildId: "testsha",
  assetCount: 2,
  assets: {
    "/_next/static/chunks/app-abc.js": sha256(APP_JS),
    "/_next/static/css/app-abc.css": sha256(APP_CSS),
  },
}

/** Knobs the fixture server uses to simulate each compromise. */
const state = {
  appJs: APP_JS,
  reportedSha: "testsha",
  extraHead: "",
}

let server: Server
let baseUrl: string
let workDir: string
let manifestPath: string

const page = () => `<!doctype html><html><head>
<link rel="stylesheet" href="/_next/static/css/app-abc.css"/>
${state.extraHead}
</head><body>
<script src="/_next/static/chunks/app-abc.js"></script>
<script data-src="/not-a-real-script.js">globalThis.x = 1</script>
<script>globalThis.y = 2</script>
</body></html>`

beforeAll(async () => {
  workDir = await mkdtemp(join(tmpdir(), "vault-integrity-"))
  manifestPath = join(workDir, "manifest.json")
  await writeFile(manifestPath, JSON.stringify(MANIFEST))

  server = createServer((req, res) => {
    const url = req.url ?? "/"
    if (url === "/api/version") {
      res.writeHead(200, { "content-type": "application/json" })
      return res.end(JSON.stringify({ sha: state.reportedSha }))
    }
    if (url === "/_next/static/chunks/app-abc.js") {
      res.writeHead(200, { "content-type": "application/javascript" })
      return res.end(state.appJs)
    }
    if (url === "/_next/static/css/app-abc.css") {
      res.writeHead(200, { "content-type": "text/css" })
      return res.end(APP_CSS)
    }
    res.writeHead(200, { "content-type": "text/html" })
    res.end(page())
  })

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve))
  const address = server.address()
  baseUrl = `http://127.0.0.1:${typeof address === "object" && address ? address.port : 0}`
})

afterAll(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()))
  await rm(workDir, { recursive: true, force: true })
})

async function check(): Promise<{ code: number, output: string }> {
  try {
    const { stdout, stderr } = await run(process.execPath, [
      "scripts/check-deployment.mjs",
      "--url",
      baseUrl,
      "--manifest",
      manifestPath,
    ])
    return { code: 0, output: stdout + stderr }
  } catch (error: any) {
    return { code: error.code ?? 1, output: (error.stdout ?? "") + (error.stderr ?? "") }
  }
}

describe("deployment integrity monitor", () => {
  it("passes a deployment serving exactly what was built", async () => {
    state.appJs = APP_JS
    state.reportedSha = "testsha"
    state.extraHead = ""

    const { code, output } = await check()
    expect(output).toContain("Assets verified byte-for-byte: 2/2")
    expect(code).toBe(0)
  })

  it("actually parses the page — a pass must not come from matching nothing", async () => {
    // The regression that motivated this file: the checker reported success
    // because its regexes matched zero resources.
    const { output } = await check()
    expect(output).toMatch(/\/: [1-9]\d* external resources/)
  })

  it("detects a modified asset", async () => {
    state.appJs = `${APP_JS}/* exfiltrate keys */\n`
    const { code, output } = await check()

    expect(output).toContain("MODIFIED: /_next/static/chunks/app-abc.js")
    expect(code).toBe(1)
    state.appJs = APP_JS
  })

  it("detects an injected off-origin script", async () => {
    state.extraHead = `<script src="https://cdn.evil.example/steal.js"></script>`
    const { code, output } = await check()

    expect(output).toContain("OFF-ORIGIN RESOURCE")
    expect(output).toContain("cdn.evil.example")
    expect(code).toBe(1)
    state.extraHead = ""
  })

  it("detects a same-origin script that was not in the build", async () => {
    state.extraHead = `<script src="/_next/static/chunks/injected-999.js"></script>`
    const { code, output } = await check()

    expect(output).toContain("UNKNOWN ASSET")
    expect(code).toBe(1)
    state.extraHead = ""
  })

  it("detects a deployment reporting a different build", async () => {
    state.reportedSha = "someothersha"
    const { code, output } = await check()

    expect(output).toContain("reports build someothersha")
    expect(code).toBe(1)
    state.reportedSha = "testsha"
  })

  it("does not mistake data-src for src", async () => {
    // The fixture page carries <script data-src="/not-a-real-script.js">.
    // Treating that as a real source would produce a permanent false positive,
    // and an alert that always fires is an alert nobody reads.
    const { code, output } = await check()
    expect(output).not.toContain("not-a-real-script")
    expect(code).toBe(0)
  })

  it("exits 2 when told to check nothing", async () => {
    try {
      await run(process.execPath, ["scripts/check-deployment.mjs", "--manifest", manifestPath])
      expect.unreachable("should have exited non-zero")
    } catch (error: any) {
      expect(error.code).toBe(2)
    }
  })
})
