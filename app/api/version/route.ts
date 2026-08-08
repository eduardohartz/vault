import { apiJson } from "@/lib/api"

/**
 * Reports which build is running.
 *
 * The integrity monitor uses this to pick the right bundle manifest to compare
 * against. It is deliberately unauthenticated: the repository is public, so the
 * commit reveals nothing, and the monitor must be able to read it without
 * holding a credential that a server compromise could steal.
 *
 * A tampered server can of course lie here — that is precisely why the monitor
 * also verifies the served asset hashes, and flags a SHA that is not a known
 * recent build.
 */
export async function GET() {
  return apiJson({
    sha: process.env.BUILD_SHA || "development",
    builtAt: process.env.BUILD_TIMESTAMP || null,
  })
}
