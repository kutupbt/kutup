import type { FederationDeliveryCounts } from '@kutup/session/api-types'

/** The kinds of delivery to other servers, in the order they are shown. */
export const DELIVERY_KINDS: FederationDeliveryCounts['kind'][] = ['chat', 'sealed', 'media', 'rename']

/** One line of a peer's deliveries that wait or were refused, by kind. */
export function peerDeliveriesLine(
  deliveries: FederationDeliveryCounts[],
  t: (key: string, options?: Record<string, unknown>) => string,
): string | null {
  const parts = DELIVERY_KINDS.flatMap(kind => {
    const counts = deliveries.find(entry => entry.kind === kind)
    if (!counts || (counts.pending === 0 && counts.rejectedLastDay === 0)) return []
    return [t('admin.federation.deliveries.peerLine', {
      kind: t(`admin.federation.deliveries.kinds.${kind}`),
      pending: counts.pending,
      rejected: counts.rejectedLastDay,
    })]
  })
  return parts.length > 0 ? parts.join(' · ') : null
}
