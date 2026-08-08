import type { NextRequest } from "next/server"
import { NextResponse } from "next/server"

/**
 * Security response headers.
 *
 * The app previously sent none. A Content-Security-Policy matters more here
 * than in a typical app: encryption keys live in this tab's memory for the
 * whole session, so any injected script could read them outright. Referrer
 * policy matters too, because share tokens travel in the URL path.
 *
 * The CSP is nonce based. Next.js reads the nonce from the request's
 * Content-Security-Policy header and stamps it onto the scripts it emits.
 */
export function middleware(request: NextRequest) {
  const nonce = Buffer.from(crypto.randomUUID()).toString("base64")

  const csp = [
    `default-src 'self'`,
    // 'strict-dynamic' lets Next's nonced bootstrap load its own chunks while
    // still refusing any script an attacker manages to inject.
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'`,
    // Inline styles are required by HeroUI and framer-motion. Inline styles
    // cannot execute script, so this is a far smaller concession than
    // 'unsafe-inline' would be for script-src.
    `style-src 'self' 'unsafe-inline'`,
    `img-src 'self' data: blob:`,
    `font-src 'self' data:`,
    // Same-origin only: file ciphertext must never be posted elsewhere.
    `connect-src 'self'`,
    `object-src 'none'`,
    `base-uri 'none'`,
    `form-action 'self'`,
    `frame-ancestors 'none'`,
    `worker-src 'self' blob:`,
  ].join("; ")

  const requestHeaders = new Headers(request.headers)
  requestHeaders.set("x-nonce", nonce)
  requestHeaders.set("Content-Security-Policy", csp)

  const response = NextResponse.next({ request: { headers: requestHeaders } })

  response.headers.set("Content-Security-Policy", csp)
  response.headers.set("X-Content-Type-Options", "nosniff")
  response.headers.set("X-Frame-Options", "DENY")
  // Keep share tokens out of Referer headers when a user follows a link away.
  response.headers.set("Referrer-Policy", "no-referrer")
  response.headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), interest-cohort=()")
  response.headers.set("Cross-Origin-Opener-Policy", "same-origin")

  // Explicit rather than inherited from Next's dynamic-page default, because
  // two things depend on it: the vault page must never be written to a disk or
  // proxy cache, and `no-store` makes the page ineligible for the back/forward
  // cache — so pressing Back cannot restore a live tab with keys still in
  // memory. SessionGuard's pageshow handler covers browsers that ignore this.
  response.headers.set("Cache-Control", "no-store, must-revalidate")

  // Only meaningful over TLS, and harmful if sent from a plain-HTTP dev server.
  if (request.nextUrl.protocol === "https:" || request.headers.get("x-forwarded-proto") === "https") {
    response.headers.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
  }

  return response
}

export const config = {
  matcher: [
    // Everything except static assets, which need no dynamic headers.
    "/((?!_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp|ico)$).*)",
  ],
}
