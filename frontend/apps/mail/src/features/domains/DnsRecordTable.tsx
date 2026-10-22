import { Copy } from 'lucide-react'
import type { ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import type { DnsRecord } from '@kutup/mail-core/domains'
import { Button } from '@kutup/ui/components/button'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@kutup/ui/components/table'
import { Tooltip } from '@kutup/ui/components/tooltip'

/** A value with Proton's copy button beside it. */
export function CopyValue({ value, copied, children }: { value: string; copied: string; children?: ReactNode }) {
  const { t } = useTranslation()
  return (
    <span className="flex min-w-0 items-center gap-1">
      <Tooltip label={t('common.copy')}>
        <Button
          type="button"
          variant="ghost"
          size="icon"
          className="size-7 shrink-0"
          aria-label={t('common.copy')}
          onClick={() => void navigator.clipboard.writeText(value).then(() => toast.success(copied))}
        >
          <Copy className="size-3.5" />
        </Button>
      </Tooltip>
      {children ?? <span className="truncate font-mono text-xs" title={value}>{value}</span>}
    </span>
  )
}

/**
 * The records a wizard step asks for (Proton's tables: Type, Host name,
 * Value / Data / Points to, and Priority for MX), each value with a copy
 * button; `copyHost` puts one beside the host name too (DKIM's).
 */
export function DnsRecordTable({
  records,
  copied,
  copyHost = false,
  value,
}: {
  records: DnsRecord[]
  /** The notification after copying. */
  copied: string
  copyHost?: boolean
  /** Shown in place of the first record's value (DMARC's editable one). */
  value?: ReactNode
}) {
  const { t } = useTranslation()
  const priority = records.some((record) => record.priority !== undefined)
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead className="w-24">{t('domains.records.type')}</TableHead>
          <TableHead>{t('domains.records.host')}</TableHead>
          <TableHead>{t('domains.records.value')}</TableHead>
          {priority ? <TableHead className="w-20">{t('domains.records.priority')}</TableHead> : null}
        </TableRow>
      </TableHeader>
      <TableBody>
        {records.map((record, i) => (
          <TableRow key={`${record.host}-${record.value}`} data-testid="dns-record">
            <TableCell className="font-mono text-xs">{record.type}</TableCell>
            <TableCell className="font-mono text-xs">
              {copyHost ? <CopyValue value={record.host} copied={copied} /> : record.host}
            </TableCell>
            <TableCell className="max-w-0">
              {i === 0 && value ? value : <CopyValue value={record.value} copied={copied} />}
            </TableCell>
            {priority ? <TableCell className="font-mono text-xs">{record.priority}</TableCell> : null}
          </TableRow>
        ))}
      </TableBody>
    </Table>
  )
}
