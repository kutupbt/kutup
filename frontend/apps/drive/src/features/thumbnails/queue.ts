// One thumbnail job at a time, in the background, so a folder upload or a
// grid full of older files never competes with what the user is doing.
// A job for a file that is already waiting replaces it: only the newest
// content matters.

type Job = () => Promise<boolean>

const waiting = new Map<string, Job>()
let running = false
let onStored: (() => void) | null = null

/** Called (debounced) after thumbnails were stored, to refresh listings. */
export function setThumbnailStoredListener(listener: (() => void) | null): void {
  onStored = listener
}

let notify: ReturnType<typeof setTimeout> | null = null
function stored(): void {
  if (notify) clearTimeout(notify)
  notify = setTimeout(() => {
    notify = null
    onStored?.()
  }, 800)
}

export function enqueueThumbnail(fileId: string, job: Job): void {
  waiting.delete(fileId)
  waiting.set(fileId, job)
  void pump()
}

async function pump(): Promise<void> {
  if (running) return
  running = true
  try {
    for (;;) {
      const next = waiting.entries().next()
      if (next.done) break
      const [fileId, job] = next.value
      waiting.delete(fileId)
      try {
        if (await job()) stored()
      } catch {
        // A preview is optional: a failure leaves the kind icon.
      }
    }
  } finally {
    running = false
  }
}
