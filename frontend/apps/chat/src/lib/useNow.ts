import { useEffect, useState } from 'react'

/** The time, updated every `intervalMs` (countdowns, "2 min ago"). */
export function useNow(intervalMs = 1_000): number {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), intervalMs)
    return () => window.clearInterval(timer)
  }, [intervalMs])
  return now
}
