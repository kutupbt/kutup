import { ChevronRight, Copy } from 'lucide-react'
import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Button } from '@kutup/ui/components/button'
import { copyText } from '@kutup/ui/lib/clipboard'
import { formatBytes, formatInstant } from '@kutup/ui/lib/format'
import type { VaultSession } from '../sync/vaultSession'
import type { CustomDataView } from '../vault/types'

/** The UUID as KeePassXC's Properties shows it: 32 hex digits. */
function uuidHex(id: string): string {
  return id.replace(/-/g, '').toLowerCase()
}

/**
 * An entry's or group's Properties (KeePassXC's `EditWidgetProperties`),
 * read-only: its UUID, when it was made and changed, and its custom data,
 * read when the section is opened.
 */
export function PropertiesSection({
  session,
  id,
  created,
  modified,
  accessed,
}: {
  session: VaultSession
  id: string
  created: string | null
  modified: string | null
  accessed?: string | null
}) {
  const { t, i18n } = useTranslation()
  const [open, setOpen] = useState(false)
  const [data, setData] = useState<CustomDataView[] | null>(null)
  const [failed, setFailed] = useState(false)
  useEffect(() => {
    if (!open) return
    let current = true
    setFailed(false)
    session
      .vault()
      .customData(id)
      .then(
        (list) => current && setData(list),
        () => current && setFailed(true),
      )
    return () => {
      current = false
    }
  }, [open, session, id])
  const hex = uuidHex(id)
  const when = (value: string | null | undefined) => (value ? formatInstant(value, i18n.language) : '—')
  return (
    <section className="mt-6" aria-label={t('properties.title')} data-testid="properties">
      <Button variant="ghost" size="sm" className="-ml-2" aria-expanded={open} onClick={() => setOpen(!open)}>
        <ChevronRight className={open ? 'rotate-90 transition-transform' : 'transition-transform'} aria-hidden />
        {t('properties.title')}
      </Button>
      {open ? (
        <div className="mt-2 space-y-3 text-sm">
          <dl className="grid grid-cols-[auto_1fr] items-center gap-x-4 gap-y-1">
            <dt className="text-muted-foreground">{t('properties.uuid')}</dt>
            <dd className="flex min-w-0 items-center gap-1">
              <code className="truncate font-mono text-xs">{hex}</code>
              <Button variant="ghost" size="icon" aria-label={t('properties.copyUuid')} onClick={() => void copyText(hex).then(() => toast.success(t('properties.uuidCopied')))}>
                <Copy />
              </Button>
            </dd>
            <dt className="text-muted-foreground">{t('properties.created')}</dt>
            <dd>{when(created)}</dd>
            <dt className="text-muted-foreground">{t('properties.modified')}</dt>
            <dd>{when(modified)}</dd>
            {accessed !== undefined ? (
              <>
                <dt className="text-muted-foreground">{t('properties.accessed')}</dt>
                <dd>{when(accessed)}</dd>
              </>
            ) : null}
          </dl>
          <div>
            <h4 className="text-xs font-medium text-muted-foreground">{t('properties.customData')}</h4>
            {failed ? (
              <p className="mt-1 text-xs text-destructive">{t('properties.failed')}</p>
            ) : data === null ? (
              <p className="mt-1 text-xs text-muted-foreground">{t('common.loading')}</p>
            ) : data.length === 0 ? (
              <p className="mt-1 text-xs text-muted-foreground">{t('properties.noCustomData')}</p>
            ) : (
              <table className="mt-1 w-full table-fixed text-xs">
                <thead className="text-left text-muted-foreground">
                  <tr>
                    <th className="w-2/5 py-1 pr-2 font-medium">{t('properties.key')}</th>
                    <th className="py-1 font-medium">{t('properties.value')}</th>
                  </tr>
                </thead>
                <tbody>
                  {data.map((item) => (
                    <tr key={item.key} className="border-t border-border align-top" data-testid="custom-data-row">
                      <td className="break-all py-1 pr-2 font-mono">{item.key}</td>
                      <td className="py-1">
                        {item.value === null ? (
                          <span className="text-muted-foreground">{t('properties.binary', { size: formatBytes(item.bytes, i18n.language) })}</span>
                        ) : (
                          <span className="block max-h-24 overflow-auto whitespace-pre-wrap break-all font-mono">{item.value}</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      ) : null}
    </section>
  )
}
