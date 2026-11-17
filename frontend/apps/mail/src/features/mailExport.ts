import { Zip, ZipPassThrough } from 'fflate'
import { placePage, storedMessage, type MailAccount, type MailMessage, type PlaceKey } from '@kutup/mail-core/api'

/** Rows a page asks for: the server's largest. */
const PAGE = 200
/** Messages opened at once. */
const AT_ONCE = 4

/** A file name for a message: when it came, then its subject, safe on every system. */
export function emlName(message: Pick<MailMessage, 'receivedAt' | 'subject'>, taken: Set<string>): string {
  const when = message.receivedAt.slice(0, 16).replace('T', ' ').replace(':', '-')
  const subject = (message.subject || 'no subject')
    .replace(/[\\/:*?"<>|\p{Cc}]/gu, '_')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 80)
  const base = `${when} ${subject}`
  let name = `${base}.eml`
  for (let n = 2; taken.has(name.toLowerCase()); n++) name = `${base} (${n}).eml`
  taken.add(name.toLowerCase())
  return name
}

export interface ExportProgress {
  done: number
  total: number
}

/**
 * A place's messages as a zip of .eml files (Proton's Export: one .eml per
 * message), each opened in this browser; nothing leaves it readable. The zip
 * streams as it is made; `signal` stops it.
 */
export async function exportPlace(account: MailAccount, place: PlaceKey, onProgress: (progress: ExportProgress) => void, signal: AbortSignal): Promise<Blob> {
  const chunks: Uint8Array[] = []
  const zipped = new Promise<Blob>((resolve, reject) => {
    const zip = new Zip((error, data, final) => {
      if (error) {
        reject(error)
        return
      }
      chunks.push(data)
      if (final) resolve(new Blob(chunks as BlobPart[], { type: 'application/zip' }))
    })
    void (async () => {
      try {
        const taken = new Set<string>()
        let page = 0
        let done = 0
        let total = 0
        for (;;) {
          const { messages, total: all } = await placePage(place, page, PAGE)
          total = Math.max(all, done + messages.length)
          onProgress({ done, total })
          for (let i = 0; i < messages.length; i += AT_ONCE) {
            if (signal.aborted) throw new Error('export stopped')
            const batch = messages.slice(i, i + AT_ONCE)
            const opened = await Promise.all(batch.map((m) => storedMessage(account, m)))
            batch.forEach((message, j) => {
              const file = new ZipPassThrough(emlName(message, taken))
              file.mtime = new Date(message.receivedAt)
              zip.add(file)
              file.push(opened[j], true)
            })
            done += batch.length
            onProgress({ done, total })
          }
          if (messages.length < PAGE) break
          page++
        }
        zip.end()
      } catch (error) {
        zip.terminate()
        reject(error instanceof Error ? error : new Error(String(error)))
      }
    })()
  })
  return zipped
}
