import { FileUp, TriangleAlert } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { Field } from '@kutup/ui/components/field'
import { Input } from '@kutup/ui/components/input'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@kutup/ui/components/select'
import { Spinner } from '@kutup/ui/components/states'
import { bytesToBase64 } from '../lib/bytes'
import type { VaultSession } from '../sync/vaultSession'
import { importFormats, importPreview } from '../vault/client'
import type { ImportFailure, ImportFormat, ImportPreview } from '../vault/types'

/** The format picker's choice for "work it out from the file" (Radix items need a value). */
const DETECT = 'detect'

function isFailure(result: ImportPreview | ImportFailure): result is ImportFailure {
  return 'error' in result
}

/**
 * Imports another password manager's CSV export into the vault: read and
 * shown first (what it found, what it would make, what it would skip), then
 * made in one step under a group of its own.
 */
export function ImportDialog({
  session,
  open,
  onOpenChange,
  onImported,
}: {
  session: VaultSession
  open: boolean
  onOpenChange: (open: boolean) => void
  /** The new group's id. */
  onImported: (groupId: string) => void
}) {
  const { t, i18n } = useTranslation()
  const input = useRef<HTMLInputElement>(null)
  const [formats, setFormats] = useState<ImportFormat[]>([])
  const [file, setFile] = useState<{ name: string; contents: Uint8Array } | null>(null)
  const [format, setFormat] = useState(DETECT)
  const [preview, setPreview] = useState<ImportPreview | null>(null)
  const [failure, setFailure] = useState<string | null>(null)
  const [reading, setReading] = useState(false)
  const [groupName, setGroupName] = useState('')
  const [importing, setImporting] = useState(false)

  useEffect(() => {
    if (!open) return
    setFile(null)
    setFormat(DETECT)
    setPreview(null)
    setFailure(null)
    setGroupName('')
    void importFormats().then(setFormats, () => setFormats([]))
  }, [open])

  // Read again whenever the file or the chosen format changes.
  useEffect(() => {
    if (!file) return
    let live = true
    setReading(true)
    setFailure(null)
    void importPreview(file.contents, format === DETECT ? null : format)
      .then((result) => {
        if (!live) return
        if (isFailure(result)) {
          setPreview(null)
          setFailure(t(`import.errors.${result.error}`, { detail: result.detail }))
        } else {
          setPreview(result)
          const date = new Intl.DateTimeFormat(i18n.language, { dateStyle: 'medium' }).format(new Date())
          setGroupName((now) => now || t('import.groupName', { app: result.providerName, date }))
        }
      })
      .catch(() => live && setFailure(t('import.errors.unreadable', { detail: '' })))
      .finally(() => live && setReading(false))
    return () => {
      live = false
    }
  }, [file, format, t, i18n.language])

  const submit = async () => {
    if (!file || !preview || !groupName.trim()) return
    setImporting(true)
    try {
      const applied = await session.apply({
        op: 'importCsv',
        data: bytesToBase64(file.contents),
        provider: preview.provider,
        groupName: groupName.trim(),
      })
      toast.success(t('import.done', { count: preview.count, group: groupName.trim() }))
      onOpenChange(false)
      if (applied.id) onImported(applied.id)
    } catch {
      setFailure(t('import.failed'))
    } finally {
      setImporting(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={(next) => !importing && onOpenChange(next)}>
      <DialogContent className="max-h-[90svh] overflow-y-auto sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>{t('import.title')}</DialogTitle>
          <DialogDescription>{t('import.description')}</DialogDescription>
        </DialogHeader>
        <div className="mt-4 space-y-4">
          <div className="flex flex-wrap items-center gap-3">
            <input
              ref={input}
              type="file"
              accept=".csv,.txt,text/csv"
              hidden
              onChange={(e) => {
                const picked = e.target.files?.[0]
                e.target.value = ''
                if (!picked) return
                void picked.arrayBuffer().then((buffer) => {
                  setPreview(null)
                  setGroupName('')
                  setFile({ name: picked.name, contents: new Uint8Array(buffer) })
                })
              }}
            />
            <Button type="button" variant="outline" onClick={() => input.current?.click()}>
              <FileUp />
              {file ? t('import.otherFile') : t('import.chooseFile')}
            </Button>
            {file ? <span className="truncate text-sm text-muted-foreground">{file.name}</span> : null}
          </div>
          <Field label={t('import.format')} description={t('import.formatDescription')}>
            {(field) => (
              <Select value={format} onValueChange={setFormat}>
                <SelectTrigger id={field.id} aria-describedby={field['aria-describedby']} className="sm:w-72">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value={DETECT}>{t('import.detect')}</SelectItem>
                  {formats.map((f) => (
                    <SelectItem key={f.id} value={f.id}>
                      {f.id === 'generic' ? t('import.generic') : f.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            )}
          </Field>
          {reading ? <Spinner label={t('import.reading')} /> : null}
          {failure ? <Alert variant="error">{failure}</Alert> : null}
          {preview && !reading ? (
            <section className="space-y-3" aria-label={t('import.preview')}>
              <p className="text-sm">
                {t('import.found', { count: preview.count, app: preview.providerName })}
                {preview.groups.length > 0 ? ` ${t('import.groups', { count: preview.groups.length })}` : ''}
              </p>
              {preview.sample.length > 0 ? (
                <div className="max-h-56 overflow-y-auto rounded-md border border-border">
                  <table className="w-full text-left text-xs">
                    <thead className="sticky top-0 bg-card text-muted-foreground">
                      <tr>
                        <th className="px-2 py-1.5 font-medium">{t('entry.title')}</th>
                        <th className="px-2 py-1.5 font-medium">{t('entry.userName')}</th>
                        <th className="px-2 py-1.5 font-medium">{t('groups.label')}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {preview.sample.map((row, index) => (
                        <tr key={index} className="border-t border-border">
                          <td className="max-w-48 truncate px-2 py-1.5">{row.title}</td>
                          <td className="max-w-40 truncate px-2 py-1.5">{row.username}</td>
                          <td className="max-w-40 truncate px-2 py-1.5">{row.group}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : null}
              {preview.count > preview.sample.length ? (
                <p className="text-xs text-muted-foreground">{t('import.more', { count: preview.count - preview.sample.length })}</p>
              ) : null}
              {preview.skipped.length > 0 ? (
                <Alert variant="warn" title={t('import.skipped', { count: preview.skipped.length })}>
                  <ul className="list-disc pl-4">
                    {preview.skipped.slice(0, 20).map((item, index) => (
                      <li key={index}>{item}</li>
                    ))}
                  </ul>
                </Alert>
              ) : null}
              {preview.warnings.length > 0 ? (
                <Alert variant="info" title={t('import.notes', { count: preview.warnings.length })}>
                  <ul className="list-disc pl-4">
                    {preview.warnings.slice(0, 20).map((item, index) => (
                      <li key={index}>{item}</li>
                    ))}
                  </ul>
                </Alert>
              ) : null}
              <Field label={t('import.into')} description={t('import.intoDescription')}>
                {(field) => <Input {...field} value={groupName} onChange={(e) => setGroupName(e.target.value)} maxLength={256} />}
              </Field>
            </section>
          ) : null}
          <p className="flex items-start gap-2 text-xs text-muted-foreground">
            <TriangleAlert className="mt-0.5 size-3.5 shrink-0" aria-hidden />
            {t('import.deleteExport')}
          </p>
        </div>
        <DialogFooter>
          <Button type="button" variant="outline" onClick={() => onOpenChange(false)} disabled={importing}>
            {t('common.cancel')}
          </Button>
          <Button type="button" onClick={() => void submit()} loading={importing} disabled={!preview || preview.count === 0 || !groupName.trim() || reading}>
            {preview ? t('import.submit', { count: preview.count }) : t('import.submitEmpty')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
