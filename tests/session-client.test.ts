import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

/**
 * Tests for session teardown.
 *
 * Motivated by a confirmed gap: only the Logout button revoked the server
 * session. The inactivity timeout merely reloaded the page, so the cookie
 * stayed valid — verified against a running server, where `/api/files` kept
 * answering 200 after the "logout".
 *
 * The module keeps a one-shot `terminating` flag, so each test imports it fresh.
 */

const LOGOUT = "/api/auth/logout"

let fetchMock: ReturnType<typeof vi.fn>
let beaconMock: ReturnType<typeof vi.fn>

async function freshModule() {
  vi.resetModules()
  return import("@/lib/session-client")
}

beforeEach(() => {
  fetchMock = vi.fn(async () => new Response(null, { status: 200 }))
  vi.stubGlobal("fetch", fetchMock)

  beaconMock = vi.fn(() => true)
  vi.stubGlobal("navigator", { sendBeacon: beaconMock })
})

afterEach(() => {
  vi.unstubAllGlobals()
})

describe("endSession", () => {
  it("revokes the session on the server", async () => {
    const { endSession } = await freshModule()
    await endSession()

    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(fetchMock.mock.calls[0][0]).toBe(LOGOUT)
    expect((fetchMock.mock.calls[0][1] as RequestInit).method).toBe("POST")
  })

  it("is idempotent, so a logout followed by unload does not revoke twice", async () => {
    const { endSession, endSessionOnUnload } = await freshModule()

    await endSession()
    endSessionOnUnload()
    await endSession()

    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(beaconMock).not.toHaveBeenCalled()
  })

  it("does not reject when the network fails", async () => {
    const { endSession } = await freshModule()
    fetchMock.mockRejectedValueOnce(new Error("offline"))

    await expect(endSession()).resolves.toBeUndefined()
  })
})

describe("endSessionOnUnload", () => {
  it("uses sendBeacon, which survives the page going away", async () => {
    const { endSessionOnUnload } = await freshModule()
    endSessionOnUnload()

    // A normal fetch is cancelled on navigation; a beacon is not.
    expect(beaconMock).toHaveBeenCalledWith(LOGOUT)
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it("falls back to keepalive fetch when the beacon queue rejects it", async () => {
    const { endSessionOnUnload } = await freshModule()
    beaconMock.mockReturnValueOnce(false)

    endSessionOnUnload()

    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect((fetchMock.mock.calls[0][1] as RequestInit).keepalive).toBe(true)
  })

  it("falls back when sendBeacon throws", async () => {
    const { endSessionOnUnload } = await freshModule()
    beaconMock.mockImplementationOnce(() => {
      throw new Error("blocked")
    })

    endSessionOnUnload()

    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  it("only fires once across repeated unload events", async () => {
    const { endSessionOnUnload } = await freshModule()

    endSessionOnUnload()
    endSessionOnUnload()

    expect(beaconMock).toHaveBeenCalledTimes(1)
  })
})

describe("cross-tab signalling", () => {
  it("delivers an end signal to another listener", async () => {
    const { broadcastSessionEnd, onSessionEndedElsewhere } = await freshModule()

    const locked = vi.fn()
    const unsubscribe = onSessionEndedElsewhere(locked)

    broadcastSessionEnd()
    await new Promise((resolve) => setTimeout(resolve, 50))

    expect(locked).toHaveBeenCalled()
    unsubscribe()
  })

  it("stops delivering after unsubscribe", async () => {
    const { broadcastSessionEnd, onSessionEndedElsewhere } = await freshModule()

    const locked = vi.fn()
    onSessionEndedElsewhere(locked)()

    broadcastSessionEnd()
    await new Promise((resolve) => setTimeout(resolve, 50))

    expect(locked).not.toHaveBeenCalled()
  })
})

describe("wipe", () => {
  it("zeroes secret material", async () => {
    const { wipe } = await freshModule()
    const buffer = new Uint8Array([1, 2, 3, 255])

    wipe(buffer)

    expect(Array.from(buffer)).toEqual([0, 0, 0, 0])
  })

  it("tolerates null and empty buffers", async () => {
    const { wipe } = await freshModule()

    expect(() => wipe(null)).not.toThrow()
    expect(() => wipe(undefined)).not.toThrow()
    expect(() => wipe(new Uint8Array(0))).not.toThrow()
  })
})
