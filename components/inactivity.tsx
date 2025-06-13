"use client"

import { useEffect, useRef } from "react"

const INACTIVITY_LIMIT_MS = 5 * 60 * 1000 // 5 minutes

export default function Inactivity() {
  const timeoutRef = useRef<NodeJS.Timeout | null>(null)

  const clearAndSetTimer = () => {
    if (timeoutRef.current) {
      clearTimeout(timeoutRef.current)
    }
    timeoutRef.current = setTimeout(() => location.reload(), INACTIVITY_LIMIT_MS)
  }

  const resetTimerOnActivity = () => clearAndSetTimer()

  const immediateReload = () => {
    if (!document.documentElement.dataset.reloading) {
      document.documentElement.dataset.reloading = "true"
      location.reload()
    }
  }

  useEffect(() => {
    clearAndSetTimer()

    const activityEvents: (keyof WindowEventMap)[] = ["mousemove", "mousedown", "keydown", "touchstart"]
    activityEvents.forEach((evt) => window.addEventListener(evt, resetTimerOnActivity))

    window.addEventListener("blur", immediateReload)
    document.addEventListener("visibilitychange", () => {
      if (document.visibilityState === "hidden") {
        immediateReload()
      }
    })

    return () => {
      if (timeoutRef.current) {
        clearTimeout(timeoutRef.current)
      }
      activityEvents.forEach((evt) => window.removeEventListener(evt, resetTimerOnActivity))
      window.removeEventListener("blur", immediateReload)
      document.removeEventListener("visibilitychange", () => {})
    }
  }, [])

  return null
}
