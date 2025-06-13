"use client"

import { useEffect, useRef } from "react"

const INACTIVITY_LIMIT_MS = 5 * 60 * 1000
const BLUR_RELOAD_DELAY_MS = 1500

export default function Inactivity() {
  const timeoutRef = useRef<NodeJS.Timeout | null>(null)
  const blurTimeoutRef = useRef<NodeJS.Timeout | null>(null)

  const clearAndSetTimer = () => {
    if (timeoutRef.current) {
      clearTimeout(timeoutRef.current)
    }
    timeoutRef.current = setTimeout(() => location.reload(), INACTIVITY_LIMIT_MS)
  }

  const resetTimerOnActivity = () => clearAndSetTimer()

  const handleBlur = () => {
    blurTimeoutRef.current = setTimeout(() => {
      if (document.visibilityState === "hidden") {
        location.reload()
      }
    }, BLUR_RELOAD_DELAY_MS)
  }

  const handleVisibilityChange = () => {
    if (document.visibilityState === "hidden") {
      location.reload()
    }
  }

  useEffect(() => {
    clearAndSetTimer()

    const activityEvents: (keyof WindowEventMap)[] = ["mousemove", "mousedown", "keydown", "touchstart"]
    activityEvents.forEach((evt) => window.addEventListener(evt, resetTimerOnActivity))

    window.addEventListener("blur", handleBlur)
    document.addEventListener("visibilitychange", handleVisibilityChange)

    return () => {
      if (timeoutRef.current) {
        clearTimeout(timeoutRef.current)
      }
      if (blurTimeoutRef.current) {
        clearTimeout(blurTimeoutRef.current)
      }

      activityEvents.forEach((evt) => window.removeEventListener(evt, resetTimerOnActivity))
      window.removeEventListener("blur", handleBlur)
      document.removeEventListener("visibilitychange", handleVisibilityChange)
    }
  }, [])

  return null
}
