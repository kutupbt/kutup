import { useState } from 'react'
import { patchVersion, type VersionRow as VR } from '../../api/collab'

interface Props {
  fileId: string
  v: VR
  onChange: (updated: VR) => void
  onRestore?: (versionId: string) => void
}

export default function VersionRow({ fileId, v, onChange, onRestore }: Props) {
  const [naming, setNaming] = useState(false)
  const [name, setName] = useState(v.label ?? '')
  const [busy, setBusy] = useState(false)

  const saveLabel = async () => {
    setBusy(true)
    try {
      const updated = await patchVersion(fileId, v.id, { label: name })
      onChange(updated)
      setNaming(false)
    } finally {
      setBusy(false)
    }
  }

  const toggleKeep = async () => {
    setBusy(true)
    try {
      const updated = await patchVersion(fileId, v.id, { keepForever: !v.keepForever })
      onChange(updated)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="p-3 hover:bg-muted">
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0 flex-1">
          <div className="text-sm font-medium">{new Date(v.createdAt).toLocaleString()}</div>
          {v.label && <div className="text-xs text-primary">{v.label}</div>}
          <div className="text-xs text-muted-foreground">
            {Math.round(v.sizeBytes / 1024)} KB · key epoch #{v.docKeyId}
            {v.keepForever && ' · kept forever'}
          </div>
        </div>
        <div className="flex shrink-0 flex-wrap gap-2 text-xs">
          <button type="button" disabled={busy} onClick={() => setNaming(true)} className="underline disabled:opacity-50">
            Name…
          </button>
          <button type="button" disabled={busy} onClick={toggleKeep} className="underline disabled:opacity-50">
            {v.keepForever ? 'Unkeep' : 'Keep forever'}
          </button>
          {onRestore && (
            <button type="button" disabled={busy} onClick={() => onRestore(v.id)} className="underline disabled:opacity-50">
              Restore
            </button>
          )}
        </div>
      </div>
      {naming && (
        <div className="mt-2 flex gap-2">
          <input
            className="flex-1 rounded border bg-background px-2 py-1 text-sm"
            value={name}
            onChange={e => setName(e.target.value)}
            disabled={busy}
            autoFocus
          />
          <button type="button" onClick={saveLabel} disabled={busy} className="text-xs">Save</button>
          <button type="button" onClick={() => { setNaming(false); setName(v.label ?? '') }} disabled={busy} className="text-xs">Cancel</button>
        </div>
      )}
    </div>
  )
}
