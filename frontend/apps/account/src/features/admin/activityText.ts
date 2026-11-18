import type { AdminActivityEntry } from '@kutup/session/api-types'
import type { useTranslation } from 'react-i18next'
import type { SettingSection } from '@kutup/session/api-types'
import { SETTING_LABELS } from './limitLabels'

type TFunction = ReturnType<typeof useTranslation>['t']

const SYSTEM_ADMIN = '00000000-0000-0000-0000-000000000000'

/**
 * Audit actions with their own sentence, under `admin.activity.actions.<key>`:
 * the action (`area.verb`) with its dot dropped (`account.create` →
 * `accountCreate`). Anything else falls back to the raw action id.
 */
const ACTIONS = new Set([
  'account.create',
  'account.update',
  'account.delete',
  'account.disableTwoFactor',
  'account.rotateTempPassword',
  'account.resetKeys',
  'account.close',
  'account.setLegalHold',
  'account.clearLegalHold',
  'account.view',
  'report.dismiss',
  'share.remove',
  'share.block',
  'share.unblock',
  'legal.publish',
  'account.setPublicSharing',
  'settings.update',
  'settings.setRateLimit',
  'account.setRateLimit',
  'account.setEntitlement',
  'registrationCode.create',
  'registrationCode.revoke',
  'maps.updateSettings',
  'mail.updateSending',
  'mail.updateOutsideSending',
  'federation.updatePolicy',
  'federation.setRule',
  'federation.deleteRule',
  'federation.createIdentity',
  'federation.rotateIdentity',
  'federation.pinPeer',
  'federation.verifyPeer',
  'federation.advancePeer',
  'federation.quarantinePeer',
  'federation.repinPeer',
  'federation.retryPeer',
  'federation.retryPeers',
])

/** The sentence's key for an action (`account.create` → `accountCreate`), if it has one. */
function actionKey(action: string): string | undefined {
  if (!ACTIONS.has(action)) return undefined
  const [area, verb] = action.split('.')
  return area + verb.charAt(0).toUpperCase() + verb.slice(1)
}

function text(value: unknown): string {
  return typeof value === 'string' || typeof value === 'number' ? String(value) : ''
}

/**
 * The limit an entry is about, as its page names it: a setting by its
 * section and field (`account.setEntitlement`), else a rate limit by its key.
 */
function limitName(e: AdminActivityEntry, t: TFunction): string {
  const field = text(e.payload.field)
  const section = text(e.payload.section) as SettingSection
  if (e.action === 'account.setEntitlement') return field && section in SETTING_LABELS ? t(`${SETTING_LABELS[section]}.${field}`) : text(e.payload.key)
  return text(e.payload.key) ? t(`admin.rateLimits.limit.${text(e.payload.key)}`) : ''
}

/**
 * One audit row as a sentence, naming accounts by their current username, or
 * "a deleted account" once they are gone (the log keeps ids only, never a
 * username).
 */
export function activitySentence(e: AdminActivityEntry, t: TFunction): string {
  const admin =
    e.adminUserId === SYSTEM_ADMIN ? t('admin.activity.system') : (e.adminUsername ?? t('admin.activity.deletedAccount'))
  const target = e.targetUsername ?? t('admin.activity.deletedAccount')
  const key = actionKey(e.action)
  const values = {
    admin,
    target,
    domain: text(e.payload.domain),
    feature: text(e.payload.feature),
    mode: text(e.payload.mode),
    // A referral code's last characters (its text is never logged).
    hint: text(e.payload.hint),
    // Outside sending's policy, as the page names it.
    from: text(e.payload.from) ? t(`admin.mailSending.policy.${text(e.payload.from)}`) : '',
    to: text(e.payload.to) ? t(`admin.mailSending.policy.${text(e.payload.to)}`) : '',
    action: e.action,
    // A rate limit or a setting by its name on the page, and its new value
    // (none: reset).
    limit: limitName(e, t),
    value: text(e.payload.value),
    // A legal hold's reference.
    reference: text(e.payload.reference),
    // A published document's kind and version.
    kind: text(e.payload.kind),
    version: text(e.payload.version),
    // An account's public links: `on` or `off`.
    state: text(e.payload.publicSharing),
  }
  // A limit set to none is reset: `<key>Reset`.
  const resets = ['settingsSetRateLimit', 'accountSetRateLimit', 'accountSetEntitlement']
  if (key && resets.includes(key) && values.value === '') return t(`admin.activity.actions.${key}Reset`, values)
  return key ? t(`admin.activity.actions.${key}`, values) : t('admin.activity.actions.unknown', values)
}
