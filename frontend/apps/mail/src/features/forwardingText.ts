import type { TFunction } from 'i18next'
import type { FilterCondition } from '@kutup/mail-core/filters'
import { ForwardeeRefused, type MailForwarding } from '@kutup/mail-core/forwardings'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'

/** Which mail a forwarding sends on, in words: everything, or its conditions. */
export function describeForwarding(forwarding: Pick<MailForwarding, 'match'> & { conditions: FilterCondition[] }, t: TFunction): string {
  if (forwarding.conditions.length === 0) return t('forwarding.everything')
  const parts = forwarding.conditions.map((condition) =>
    condition.field === 'attachments'
      ? t(condition.negate ? 'filters.noAttachments' : 'filters.hasAttachments')
      : `${t(`filters.fields.${condition.field}`)} ${t(condition.negate ? `filters.notOps.${condition.op}` : `filters.ops.${condition.op}`)} “${condition.value}”`,
  )
  return parts.join(forwarding.match === 'all' ? t('forwarding.and') : t('forwarding.or'))
}

/** Refusals with their own words (the server's codes, and the client's own checks). */
const CODES: Record<string, string> = {
  // Mail's own rules: the composer's words.
  outsideSendingOff: 'compose.outsideOffNotice',
  sendingPaused: 'compose.sendingPaused',
  forwardingExists: 'forwarding.errors.exists',
  forwardingLimit: 'forwarding.errors.limit',
  forwardingUnavailable: 'forwarding.errors.unavailable',
  internationalAddressUnsupported: 'forwarding.errors.international',
  endToEndRequired: 'forwarding.errors.endToEndRequired',
  keyListRequired: 'forwarding.errors.keyList',
  keyListMismatch: 'forwarding.errors.keyList',
  forwardingMaterialMismatch: 'forwarding.errors.keyList',
  forwardingKeepsNoEncrypt: 'forwarding.errors.keyList',
  forwardingState: 'forwarding.errors.state',
  forwardingVerified: 'forwarding.errors.state',
  rateLimited: 'forwarding.errors.rateLimited',
}

/** A forwarding action's failure, in the user's language where it has words. */
export function forwardingErrorMessage(error: unknown, t: TFunction, fallback = t('common.tryAgain')): string {
  if (error instanceof ForwardeeRefused) return t(`forwarding.errors.${error.reason}`)
  const code = (error as { response?: { data?: { code?: unknown } } }).response?.data?.code
  if (typeof code === 'string' && CODES[code]) return t(CODES[code])
  return apiErrorMessage(error, fallback)
}
