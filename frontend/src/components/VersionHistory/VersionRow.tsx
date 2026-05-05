import { useState } from 'react'
import { Pin, PinOff, Pencil, RotateCcw, Loader2 } from 'lucide-react'
import { patchVersion, type VersionRow as VR } from '../../api/collab'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { cn } from '@/lib/utils'

interface Props {
  fileId: string
  v: VR
  onChange: (updated: VR) => void
  onRestore?: (versionId: string) => void
}

function formatTimestamp(iso: string): string {
  const d = new Date(iso)
  const now = new Date()
  const same = d.toDateString() === now.toDateString()
  const time = d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })
  if (same) return `Today, ${time}`
  const yesterday = new Date(now); yesterday.setDate(now.getDate() - 1)
  if (d.toDateString() === yesterday.toDateString()) return `Yesterday, ${time}`
  const sameYear = d.getFullYear() === now.getFullYear()
  return `${d.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: sameYear ? undefined : 'numeric' })}, ${time}`
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

export default function VersionRow({ fileId, v, onChange, onRestore }: Props) {
  const [naming, setNaming] = useState(false)
  const [name, setName] = useState(v.label ?? '')
  const [busy, setBusy] = useState(false)

  async function saveLabel() {
    setBusy(true)
    try {
      const updated = await patchVersion(fileId, v.id, { label: name })
      onChange(updated)
      setNaming(false)
    } finally {
      setBusy(false)
    }
  }

  async function toggleKeep() {
    setBusy(true)
    try {
      const updated = await patchVersion(fileId, v.id, { keepForever: !v.keepForever })
      onChange(updated)
    } finally {
      setBusy(false)
    }
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
            'mt-1 h-2 w-2 shrink-0 rounded-full',
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
                <Pin className="h-2.5 w-2.5" /> kept
              </span>
            )}
          </div>
          {v.label && (
            <div className="mt-0.5 text-xs text-muted-foreground">
              {formatTimestamp(v.createdAt)}
            </div>
          )}
          <div className="mt-1 text-xs text-muted-foreground">
            {formatSize(v.sizeBytes)} · epoch #{v.docKeyId}
          </div>

          {naming ? (
            <div className="mt-2 flex items-center gap-2">
              <Input
                value={name}
                onChange={(e) => setName(e.target.value)}
                disabled={busy}
                autoFocus
                placeholder="Version name…"
                className="h-8 text-sm"
                onKeyDown={(e) => {
                  if (e.key === 'Enter') { e.preventDefault(); saveLabel() }
                  if (e.key === 'Escape') { setNaming(false); setName(v.label ?? '') }
                }}
              />
              <Button size="sm" variant="default" disabled={busy} onClick={saveLabel}>
                {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : 'Save'}
              </Button>
              <Button size="sm" variant="ghost" disabled={busy} onClick={() => { setNaming(false); setName(v.label ?? '') }}>
                Cancel
              </Button>
            </div>
          ) : (
            <div className="mt-2 flex flex-wrap gap-1 opacity-0 transition-opacity group-hover:opacity-100">
              <Button
                type="button"
                size="sm"
                variant="ghost"
                disabled={busy}
                onClick={() => setNaming(true)}
                className="h-7 gap-1 px-2 text-xs"
              >
                <Pencil className="h-3 w-3" /> Name
              </Button>
              <Button
                type="button"
                size="sm"
                variant="ghost"
                disabled={busy}
                onClick={toggleKeep}
                className="h-7 gap-1 px-2 text-xs"
              >
                {v.keepForever
                  ? <><PinOff className="h-3 w-3" /> Unkeep</>
                  : <><Pin className="h-3 w-3" /> Keep</>}
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
                  <RotateCcw className="h-3 w-3" /> Restore
                </Button>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
