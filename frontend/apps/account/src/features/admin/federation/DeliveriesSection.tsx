import { useTranslation } from 'react-i18next'
import type { FederationDeliveryCounts } from '@kutup/session/api-types'
import { Card } from '@kutup/ui/components/card'
import { formatInstant } from '@kutup/ui/lib/format'
import { DELIVERY_KINDS } from './deliveries'

/**
 * Deliveries to other servers by kind (docs/plans/federation-outbox.md):
 * what is still to go, the oldest of it, and what was refused for good in the
 * last day.
 */
export function DeliveriesSection({ deliveries }: { deliveries: FederationDeliveryCounts[] }) {
  const { t, i18n } = useTranslation()
  const byKind = new Map(deliveries.map(counts => [counts.kind, counts]))
  return (
    <Card className="overflow-x-auto p-0">
      <table className="w-full text-sm" data-testid="federation-deliveries">
        <thead className="text-left text-xs uppercase tracking-wide text-muted-foreground">
          <tr>
            <th className="p-3 font-medium">{t('admin.federation.deliveries.kind')}</th>
            <th className="p-3 font-medium">{t('admin.federation.deliveries.pending')}</th>
            <th className="p-3 font-medium">{t('admin.federation.deliveries.oldest')}</th>
            <th className="p-3 font-medium">{t('admin.federation.deliveries.rejected')}</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-border">
          {DELIVERY_KINDS.map(kind => {
            const counts = byKind.get(kind)
            return (
              <tr key={kind} data-kind={kind}>
                <td className="p-3">{t(`admin.federation.deliveries.kinds.${kind}`)}</td>
                <td className="p-3 tabular-nums">{counts?.pending ?? 0}</td>
                <td className="p-3">
                  {counts?.oldestPendingAt ? formatInstant(counts.oldestPendingAt, i18n.language) : '—'}
                </td>
                <td className="p-3 tabular-nums">{counts?.rejectedLastDay ?? 0}</td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </Card>
  )
}
