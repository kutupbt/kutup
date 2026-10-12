import { FileKey2, X } from 'lucide-react'
import { useRef } from 'react'
import { useTranslation } from 'react-i18next'
import { Button } from '@kutup/ui/components/button'

/** Picks a KeePass key file; it is read here and never uploaded as a file. */
export function KeyFileInput({
  value,
  onChange,
}: {
  value: { name: string; contents: Uint8Array } | null
  onChange: (value: { name: string; contents: Uint8Array } | null) => void
}) {
  const { t } = useTranslation()
  const input = useRef<HTMLInputElement>(null)
  return (
    <div className="flex items-center gap-2">
      <input
        ref={input}
        type="file"
        hidden
        onChange={(e) => {
          const file = e.target.files?.[0]
          e.target.value = ''
          if (!file) return
          void file.arrayBuffer().then((buffer) => onChange({ name: file.name, contents: new Uint8Array(buffer) }))
        }}
      />
      {value ? (
        <>
          <span className="flex min-w-0 items-center gap-1.5 text-sm">
            <FileKey2 className="size-4 shrink-0 text-muted-foreground" aria-hidden />
            <span className="truncate">{value.name}</span>
          </span>
          <Button type="button" variant="ghost" size="icon" onClick={() => onChange(null)} aria-label={t('keyFile.remove')}>
            <X />
          </Button>
        </>
      ) : (
        <Button type="button" variant="outline" size="sm" onClick={() => input.current?.click()}>
          <FileKey2 />
          {t('keyFile.choose')}
        </Button>
      )}
    </div>
  )
}
