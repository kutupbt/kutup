import { RotateCcw } from 'lucide-react'
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useFolders } from '@kutup/drive-core/folders'
import type { Folder } from '@kutup/drive-core/model'
import { pendingUploads, runningUploads, type PendingUpload } from '@kutup/files/upload/pendingUploads'
import { pendingUploadName } from '@kutup/files/upload/streamUpload'
import api from '@kutup/session/client'
import { Button } from '@kutup/ui/components/button'
import { formatBytes } from '@kutup/ui/lib/format'
import { useUploads } from './uploadStore'

/** What an app gives the upload panel so interrupted uploads can go on. */
export interface ResumeSetup {
  /** The signed-in account: only its uploads are offered. */
  owner: string
  /** Queue the resumed upload (and what follows one in this app, a thumbnail). */
  onResume: (upload: PendingUpload, file: File, folder: Folder) => void
}

interface Entry {
  upload: PendingUpload
  folder: Folder | undefined
  /** Null while its name is read; undefined when the folder's key moved on. */
  name: string | null | undefined
}

/**
 * Uploads a reload or a crash stopped, this account's, in this app: each can
 * go on once the same file is chosen again (a page cannot open it by
 * itself), or be let go, which also frees what the server holds of it.
 */
export function InterruptedUploads({ setup, onCount }: { setup: ResumeSetup; onCount: (count: number) => void }) {
  const { t, i18n } = useTranslation()
  const folders = useFolders()
  const jobs = useUploads()
  const [stopped, setStopped] = useState<PendingUpload[]>([])
  const [names, setNames] = useState(new Map<string, string | undefined>())
  const [busy, setBusy] = useState<string | null>(null)
  const pickers = useRef(new Map<string, HTMLInputElement | null>())
  // Handed to the queue here: not offered again while it starts (before
  // its run takes the lock that marks it running).
  const resumedHere = useRef(new Set<string>())

  const refresh = useCallback(async () => {
    try {
      const [pending, running] = await Promise.all([pendingUploads.list(setup.owner), runningUploads()])
      const ids = new Set(pending.map((upload) => upload.fileId))
      for (const id of resumedHere.current) if (!ids.has(id)) resumedHere.current.delete(id)
      setStopped(pending.filter((upload) => !running.has(upload.fileId) && !resumedHere.current.has(upload.fileId)))
    } catch {
      setStopped([])
    }
  }, [setup.owner])

  // Again whenever the queue moves: a resumed upload runs, then is done.
  const queueState = jobs.map((job) => `${job.id}:${job.status}`).join(',')
  useEffect(() => {
    void refresh()
  }, [refresh, queueState])

  const index = folders.data
  useEffect(() => {
    let current = true
    for (const upload of stopped) {
      if (names.has(upload.fileId)) continue
      const folder = index?.byId.get(upload.collectionId)
      if (!folder?.key) continue
      if (folder.keyEpoch !== upload.keyEpoch) {
        setNames((known) => new Map(known).set(upload.fileId, undefined))
        continue
      }
      void pendingUploadName(upload, folder.key)
        .then((metadata) => current && setNames((known) => new Map(known).set(upload.fileId, metadata.name)))
        .catch(() => current && setNames((known) => new Map(known).set(upload.fileId, undefined)))
    }
    return () => {
      current = false
    }
  }, [stopped, index, names])

  useEffect(() => {
    onCount(stopped.length)
  }, [stopped.length, onCount])

  const entries: Entry[] = useMemo(
    () =>
      stopped.map((upload) => ({
        upload,
        folder: index?.byId.get(upload.collectionId),
        name: names.has(upload.fileId) ? names.get(upload.fileId) : null,
      })),
    [stopped, index, names],
  )

  async function discard(upload: PendingUpload) {
    setBusy(upload.fileId)
    try {
      // What the server holds of it goes too; one it already let go is fine.
      await api.delete(`/uploads/${encodeURIComponent(upload.uploadUrl.split('/').filter(Boolean).at(-1) ?? '')}`, {
        headers: { 'Tus-Resumable': '1.0.0' },
      }).catch(() => undefined)
      await pendingUploads.remove(upload.fileId)
      await refresh()
    } finally {
      setBusy(null)
    }
  }

  if (entries.length === 0) return null
  return (
    <section aria-label={t('uploads.interruptedTitle')} className="border-b border-border">
      <div className="px-4 pb-1 pt-2.5">
        <p className="text-sm font-medium">{t('uploads.interruptedTitle')}</p>
        <p className="text-xs text-muted-foreground">{t('uploads.interruptedHint')}</p>
      </div>
      <ul className="divide-y divide-border">
        {entries.map(({ upload, folder, name }) => {
          const readable = typeof name === 'string' && folder !== undefined
          const label = readable ? name : t('uploads.unreadable')
          const folderName = folder ? (folder.isRoot ? t('uploads.myFiles') : (folder.name ?? '')) : ''
          return (
            <li key={upload.fileId} className="space-y-1.5 px-4 py-2.5" data-testid="interrupted-upload">
              <div className="flex items-center gap-2 text-sm">
                <span className="min-w-0 flex-1 truncate" title={label ?? ''}>
                  {name === null ? '…' : label}
                </span>
              </div>
              <p className="text-xs text-muted-foreground">
                {[folderName ? t('uploads.intoFolder', { folder: folderName }) : null, formatBytes(upload.size, i18n.language)]
                  .filter(Boolean)
                  .join(' · ')}
              </p>
              <div className="flex gap-2">
                {readable ? (
                  <>
                    <input
                      ref={(element) => {
                        pickers.current.set(upload.fileId, element)
                      }}
                      type="file"
                      className="hidden"
                      aria-hidden
                      tabIndex={-1}
                      data-testid="interrupted-upload-file"
                      onChange={(event) => {
                        const file = event.target.files?.[0]
                        event.target.value = ''
                        if (!file || !folder) return
                        resumedHere.current.add(upload.fileId)
                        setStopped((list) => list.filter((u) => u.fileId !== upload.fileId))
                        setup.onResume(upload, file, folder)
                      }}
                    />
                    <Button
                      size="sm"
                      variant="outline"
                      disabled={busy === upload.fileId}
                      aria-label={t('uploads.resumeNamed', { name: label })}
                      onClick={() => pickers.current.get(upload.fileId)?.click()}
                    >
                      <RotateCcw /> {t('uploads.resume')}
                    </Button>
                  </>
                ) : null}
                <Button
                  size="sm"
                  variant="ghost"
                  loading={busy === upload.fileId}
                  aria-label={t('uploads.discardNamed', { name: label })}
                  onClick={() => void discard(upload)}
                >
                  {t('uploads.discard')}
                </Button>
              </div>
            </li>
          )
        })}
      </ul>
    </section>
  )
}
