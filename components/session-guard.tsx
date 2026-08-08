"use client"

import { useEffect, useRef } from "react"
import { endSession, endSessionOnUnload, onSessionEndedElsewhere } from "@/lib/session-client"

/** Idle time before the vault locks itself. */
const INACTIVITY_LIMIT_MS = 5 * 60 * 1000

/**
 * How long the page may stay hidden before the session ends.
 *
 * An earlier version locked the instant `visibilitychange` fired, which happens
 * on every tab switch and — critically — when the OS file picker takes focus,
 * so uploading a file could log you out mid-action. A short grace period keeps
 * the protection without breaking normal use.
 */
const HIDDEN_GRACE_MS = 60 * 1000

type SessionGuardProps = {
  /** Tear down client-side state. The server session is already revoked. */
  onExpire: () => void
}

/**
 * Ends the vault session on idle, on leaving the page, and across tabs.
 *
 * Encryption keys live only in this tab's memory, so locking the UI is half the
 * job — the server session has to die with it. Every exit path below revokes it
 * server-side; previously only the Logout button did, and the inactivity
 * timeout left a usable cookie behind for the rest of its lifetime.
 */
export default function SessionGuard({ onExpire }: SessionGuardProps) {
  const idleTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const hiddenTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const expiredRef = useRef(false)
  const onExpireRef = useRef(onExpire)

  useEffect(() => {
    onExpireRef.current = onExpire
  }, [onExpire])

  useEffect(() => {
    const clearTimers = () => {
      if (idleTimerRef.current) {
        clearTimeout(idleTimerRef.current)
        idleTimerRef.current = null
      }
      if (hiddenTimerRef.current) {
        clearTimeout(hiddenTimerRef.current)
        hiddenTimerRef.current = null
      }
    }

    /** Full teardown while the page is still alive. */
    const expire = () => {
      if (expiredRef.current) {
        return
      }
      expiredRef.current = true
      clearTimers()

      void endSession().finally(() => onExpireRef.current())
    }

    /** Another tab already revoked the session; just lock this one. */
    const lockLocally = () => {
      if (expiredRef.current) {
        return
      }
      expiredRef.current = true
      clearTimers()
      onExpireRef.current()
    }

    const resetIdleTimer = () => {
      if (expiredRef.current) {
        return
      }
      if (idleTimerRef.current) {
        clearTimeout(idleTimerRef.current)
      }
      idleTimerRef.current = setTimeout(expire, INACTIVITY_LIMIT_MS)
    }

    const handleVisibilityChange = () => {
      if (document.visibilityState === "hidden") {
        hiddenTimerRef.current = setTimeout(expire, HIDDEN_GRACE_MS)
        return
      }

      if (hiddenTimerRef.current) {
        clearTimeout(hiddenTimerRef.current)
        hiddenTimerRef.current = null
      }
      resetIdleTimer()
    }

    /**
     * The page is going away — closed, navigated away from, or moved into the
     * back/forward cache. This is the last reliable moment to revoke the
     * session, and it must use a beacon because a normal fetch would be
     * cancelled.
     */
    const handlePageHide = () => {
      clearTimers()
      endSessionOnUnload()
    }

    /**
     * Restored from the back/forward cache.
     *
     * bfcache preserves the whole JS heap, so pressing Back would otherwise
     * bring the vault back fully unlocked — decrypted filenames still on screen
     * and keys still in memory — however long the user was away. Reload so that
     * memory is discarded and the passkey is required again.
     */
    const handlePageShow = (event: PageTransitionEvent) => {
      if (event.persisted) {
        window.location.reload()
      }
    }

    resetIdleTimer()

    const activityEvents: (keyof WindowEventMap)[] = ["mousemove", "mousedown", "keydown", "touchstart", "scroll"]
    activityEvents.forEach((evt) => window.addEventListener(evt, resetIdleTimer, { passive: true }))
    document.addEventListener("visibilitychange", handleVisibilityChange)
    window.addEventListener("pagehide", handlePageHide)
    window.addEventListener("pageshow", handlePageShow)

    const unsubscribe = onSessionEndedElsewhere(lockLocally)

    return () => {
      clearTimers()
      activityEvents.forEach((evt) => window.removeEventListener(evt, resetIdleTimer))
      document.removeEventListener("visibilitychange", handleVisibilityChange)
      window.removeEventListener("pagehide", handlePageHide)
      window.removeEventListener("pageshow", handlePageShow)
      unsubscribe()
    }
  }, [])

  return null
}
