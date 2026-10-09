import { useSyncExternalStore } from 'react'

/** `skipped`: nothing was uploaded (`skipReason` says why). */
export type UploadStatus = 'queued' | 'uploading' | 'done' | 'skipped' | 'failed' | 'cancelled'

/**
 * Why nothing was uploaded: `library`, the Photos library already has it;
 * `here`, the same file is already in the folder under that name; `chosen`,
 * its name was taken and the person chose to skip it
 * (docs/plans/drive-unique-names.md).
 */
export type SkipReason = 'library' | 'here' | 'chosen'

/** What a job's `run` resolves: uploaded, or skipped and why (`skipped` is `library`). */
export type UploadOutcome = void | 'skipped' | { skipped: SkipReason }

export interface UploadJob {
  id: string
  name: string
  /** The folder it goes into (display only). */
  folderName: string
  sent: number
  total: number
  /** What `sent`/`total` count: bytes (a file) or files (a folder). */
  unit?: 'bytes' | 'files'
  status: UploadStatus
  /** The connection is gone; the upload waits and goes on where it stopped. */
  waiting?: boolean
  failure?: import('./uploadError').UploadFailure
  skipReason?: SkipReason
  /** Resolves skipped (with why) when nothing was uploaded. */
  run: (
    signal: AbortSignal,
    progress: (sent: number, total: number) => void,
    waiting: (waiting: boolean) => void,
  ) => Promise<UploadOutcome>
  controller: AbortController
}

let jobs: UploadJob[] = []
const listeners = new Set<() => void>()
let running = false

function emit(next: UploadJob[]) {
  jobs = next
  for (const l of listeners) l()
}

function patch(id: string, update: Partial<UploadJob>) {
  emit(jobs.map((j) => (j.id === id ? { ...j, ...update } : j)))
}

async function pump(onSettled: () => void, classify: (error: unknown) => UploadJob['failure']) {
  if (running) return
  running = true
  try {
    for (;;) {
      const job = jobs.find((j) => j.status === 'queued')
      if (!job) break
      patch(job.id, { status: 'uploading' })
      try {
        const outcome = await job.run(
          job.controller.signal,
          (sent, total) => patch(job.id, { sent, total }),
          (waiting) => patch(job.id, { waiting }),
        )
        const skipReason = outcome === 'skipped' ? 'library' : outcome ? outcome.skipped : null
        patch(job.id, skipReason ? { status: 'skipped', skipReason, waiting: false } : { status: 'done', sent: job.total, waiting: false })
      } catch (error) {
        const aborted = error instanceof DOMException && error.name === 'AbortError'
        patch(job.id, aborted ? { status: 'cancelled', waiting: false } : { status: 'failed', waiting: false, failure: classify(error) })
      }
      onSettled()
    }
  } finally {
    running = false
  }
}

/**
 * The upload queue, shared by every page in the tab: one upload at a time,
 * in the order they were added, each cancellable. `onSettled` runs after each
 * job (refresh the list and the storage meter).
 */
export const uploads = {
  add(
    items: Omit<UploadJob, 'id' | 'status' | 'sent' | 'controller'>[],
    onSettled: () => void,
    classify: (error: unknown) => UploadJob['failure'],
  ) {
    const added = items.map((item) => ({
      ...item,
      id: crypto.randomUUID(),
      status: 'queued' as const,
      sent: 0,
      controller: new AbortController(),
    }))
    emit([...jobs, ...added])
    void pump(onSettled, classify)
  },
  cancel(id: string) {
    const job = jobs.find((j) => j.id === id)
    if (!job) return
    job.controller.abort()
    if (job.status === 'queued') patch(id, { status: 'cancelled' })
  },
  cancelAll() {
    for (const job of jobs) if (job.status === 'queued' || job.status === 'uploading') uploads.cancel(job.id)
  },
  clearFinished() {
    emit(jobs.filter((j) => j.status === 'queued' || j.status === 'uploading'))
  },
  subscribe: (listener: () => void) => {
    listeners.add(listener)
    return () => {
      listeners.delete(listener)
    }
  },
  snapshot: () => jobs,
}

export function useUploads(): UploadJob[] {
  return useSyncExternalStore(uploads.subscribe, uploads.snapshot)
}
