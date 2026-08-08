/**
 * Client-side session teardown.
 *
 * Every path that ends a session must revoke it on the server too. Previously
 * only the Logout button did: the inactivity timeout just reloaded the page, so
 * the cookie stayed valid for the remainder of its TTL. Verified before the
 * fix — after the timeout, `/api/files` still answered 200 for the same cookie.
 */

const LOGOUT_ENDPOINT = "/api/auth/logout"
const CHANNEL_NAME = "vault-session"

/**
 * Guards against firing teardown twice — a reload triggers `pagehide`, so an
 * intentional logout would otherwise beacon a second time on the way out.
 */
let terminating = false

/**
 * End the session: tell other tabs, then revoke it on the server.
 *
 * Use for deliberate logout and for timeouts, where the page is still alive
 * long enough for a normal request to complete.
 */
export async function endSession(): Promise<void> {
  if (terminating) {
    return
  }
  terminating = true

  broadcastSessionEnd()

  try {
    await fetch(LOGOUT_ENDPOINT, { method: "POST" })
  } catch (error) {
    console.error("Failed to revoke session:", error)
  }
}

/**
 * End the session while the page is being torn down.
 *
 * sendBeacon is the only request the browser promises to deliver once the page
 * is gone; an ordinary fetch is cancelled on navigation. keepalive is the
 * fallback if the beacon queue rejects it.
 */
export function endSessionOnUnload(): void {
  if (terminating) {
    return
  }
  terminating = true

  broadcastSessionEnd()

  try {
    if (navigator.sendBeacon?.(LOGOUT_ENDPOINT)) {
      return
    }
  } catch {
    // Fall through.
  }

  try {
    void fetch(LOGOUT_ENDPOINT, { method: "POST", keepalive: true })
  } catch {
    // Nothing more is possible during unload.
  }
}

function openChannel(): BroadcastChannel | null {
  if (typeof BroadcastChannel === "undefined") {
    return null
  }
  try {
    return new BroadcastChannel(CHANNEL_NAME)
  } catch {
    return null
  }
}

/** Tell other tabs of this vault to lock themselves. */
export function broadcastSessionEnd(): void {
  const channel = openChannel()
  if (!channel) {
    return
  }
  try {
    channel.postMessage("ended")
  } finally {
    channel.close()
  }
}

/** Listen for another tab ending the session. Returns an unsubscribe function. */
export function onSessionEndedElsewhere(handler: () => void): () => void {
  const channel = openChannel()
  if (!channel) {
    return () => {}
  }

  const listener = (event: MessageEvent) => {
    if (event.data === "ended") {
      handler()
    }
  }

  channel.addEventListener("message", listener)

  return () => {
    channel.removeEventListener("message", listener)
    channel.close()
  }
}

/**
 * Overwrite a buffer holding secret material.
 *
 * Best effort only: the JS engine may already have copied the bytes during GC,
 * and the underlying assertion buffer is not ours to clear. It costs nothing
 * and shortens the window in which the PRF output — from which every key
 * rederives — sits readable in the heap.
 */
export function wipe(buffer: Uint8Array | null | undefined): void {
  if (buffer && buffer.length > 0) {
    buffer.fill(0)
  }
}
