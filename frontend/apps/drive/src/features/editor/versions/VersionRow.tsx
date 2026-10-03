import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Pin, PinOff, Pencil, RotateCcw, Loader2 } from 'lucide-react'
import { patchVersion, type VersionRow as VR } from '@kutup/collab/api'
import { Button } from '@kutup/ui/components/button'
import { Input } from '@kutup/ui/components/input'
import { cn } from '@kutup/ui/lib/cn'
import { formatBytes } from '@kutup/ui/lib/format'

interface Props {
  fileId: string
  v: VR
  onChange: (updated: VR) => void
  onRestore?: (versionId: string) => void
  /** View-only access: the history is shown, not changed. */
  readOnly?: boolean
  /** A file on another server: its calls go through this server. */
  base?: string
}

export default function VersionRow({ fileId, v, onChange, onRestore, readOnly = false, base }: Props) {
  const { t, i18n } = useTranslation()
  const [naming, setNaming] = useState(false)
  const [name, setName] = useState(v.label ?? '')
  const [busy, setBusy] = useState(false)

  function formatTimestamp(iso: string): string {
    const d = new Date(iso)
    const now = new Date()
    const time = d.toLocaleTimeString(i18n.language, { hour: '2-digit', minute: '2-digit' })
    if (d.toDateString() === now.toDateString()) return t('editor.versions.today', { time })
    const yesterday = new Date(now)
    yesterday.setDate(now.getDate() - 1)
    if (d.toDateString() === yesterday.toDateString()) return t('editor.versions.yesterday', { time })
    const sameYear = d.getFullYear() === now.getFullYear()
    const date = d.toLocaleDateString(i18n.language, {
      month: 'short',
      day: 'numeric',
      year: sameYear ? undefined : 'numeric',
    })
    return `${date}, ${time}`
  }

  async function update(patch: Parameters<typeof patchVersion>[2]): Promise<boolean> {
    setBusy(true)
    try {
      onChange(await patchVersion(fileId, v.id, patch, base))
      return true
    } catch {
      toast.error(t('editor.versions.updateFailed'))
      return false
    } finally {
      setBusy(false)
    }
  }

  async function saveLabel() {
    if (await update({ label: name.trim() })) setNaming(false)
  }

  function cancelNaming() {
    setNaming(false)
    setName(v.label ?? '')
  }

  return (
    <div
      className={cn(
        'group relative px-4 py-3 transition-colors hover:bg-accent/40',
        v.keepForever && 'bg-primary/5',
      )}
    >
      <div className="flex items-start gap-3">
        <div
          className={cn(
            'mt-1.5 size-2 shrink-0 rounded-full',
            v.keepForever ? 'bg-primary' : 'bg-muted-foreground/40',
          )}
          aria-hidden
        />
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="truncate text-sm font-medium">
              {v.label || formatTimestamp(v.createdAt)}
            </span>
            {v.keepForever && (
              <span className="inline-flex items-center gap-1 rounded-full bg-primary/15 px-2 py-0.5 text-[10px] font-medium text-primary">
                <Pin className="size-2.5" aria-hidden /> {t('editor.versions.kept')}
              </span>
            )}
          </div>
          {v.label && (
            <div className="mt-0.5 text-xs text-muted-foreground">{formatTimestamp(v.createdAt)}</div>
          )}
          <div className="mt-1 text-xs text-muted-foreground">
            {t('editor.versions.meta', { size: formatBytes(v.sizeBytes, i18n.language), key: v.docKeyId })}
          </div>

          {readOnly ? null : naming ? (
            <div className="mt-2 flex items-center gap-2">
              <Input
                value={name}
                onChange={(e) => setName(e.target.value)}
                disabled={busy}
                autoFocus
                maxLength={200}
                placeholder={t('editor.versions.namePlaceholder')}
                aria-label={t('editor.versions.namePlaceholder')}
                className="h-8 text-sm"
                onKeyDown={(e) => {
                  if (e.key === 'Enter') { e.preventDefault(); void saveLabel() }
                  if (e.key === 'Escape') cancelNaming()
                }}
              />
              <Button size="sm" disabled={busy} onClick={() => void saveLabel()}>
                {busy ? <Loader2 className="animate-spin" aria-hidden /> : t('common.save')}
              </Button>
              <Button size="sm" variant="ghost" disabled={busy} onClick={cancelNaming}>
                {t('common.cancel')}
              </Button>
            </div>
          ) : (
            <div className="mt-2 flex flex-wrap gap-1 transition-opacity md:opacity-0 md:group-hover:opacity-100 md:group-focus-within:opacity-100">
              <Button
                type="button"
                size="sm"
                variant="ghost"
                disabled={busy}
                onClick={() => setNaming(true)}
                className="h-7 gap-1 px-2 text-xs"
              >
                <Pencil className="size-3" aria-hidden /> {t('editor.versions.name')}
              </Button>
              <Button
                type="button"
                size="sm"
                variant="ghost"
                disabled={busy}
                onClick={() => void update({ keepForever: !v.keepForever })}
                className="h-7 gap-1 px-2 text-xs"
              >
                {v.keepForever ? (
                  <><PinOff className="size-3" aria-hidden /> {t('editor.versions.unkeep')}</>
                ) : (
                  <><Pin className="size-3" aria-hidden /> {t('editor.versions.keep')}</>
                )}
              </Button>
              {onRestore && (
                <Button
                  type="button"
                  size="sm"
                  variant="ghost"
                  disabled={busy}
                  onClick={() => onRestore(v.id)}
                  className="h-7 gap-1 px-2 text-xs"
                >
                  <RotateCcw className="size-3" aria-hidden /> {t('editor.versions.restore')}
                </Button>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
