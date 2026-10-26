import type { AdminActivityEntry } from '@kutup/session/api-types'
import type { useTranslation } from 'react-i18next'
import type { SettingSection } from '@kutup/session/api-types'
import { SETTING_LABELS } from './limitLabels'

type TFunction = ReturnType<typeof useTranslation>['t']

const SYSTEM_ADMIN = '00000000-0000-0000-0000-000000000000'

/** Audit actions with their own sentence; anything else falls back to the raw action id. */
const ACTION_KEYS: Record<string, string> = {
  'user.create': 'userCreate',
  'user.update': 'userUpdate',
  'user.delete': 'userDelete',
  'user.2fa_disable': 'user2faDisable',
  'user.rotate_temp_password': 'userRotateTempPassword',
  'user.wipe': 'userWipe',
  'report.dismiss': 'reportDismiss',
  'share.remove': 'shareRemove',
  'settings.update': 'settingsUpdate',
  'settings.rate_limit': 'rateLimitUpdate',
  'user.rate_limit': 'userRateLimitUpdate',
  'user.setting': 'userSettingUpdate',
  'registration_code.created': 'registrationCodeCreated',
  'registration_code.revoked': 'registrationCodeRevoked',
  'maps.settings.update': 'mapsSettingsUpdate',
  'mail.sending.update': 'mailSendingUpdate',
  'mail.outside_sending.update': 'mailOutsideSendingUpdate',
  'federation.policy.update': 'federationPolicyUpdate',
  'federation.rule.upsert': 'federationRuleUpsert',
  'federation.rule.delete': 'federationRuleDelete',
  'federation.identity.genesis': 'federationIdentityGenesis',
  'federation.identity.rotate-local': 'federationIdentityRotateLocal',
  'federation.identity.pin': 'federationIdentityPin',
  'federation.identity.verify': 'federationIdentityVerify',
  'federation.identity.advance-remote': 'federationIdentityAdvance',
  'federation.identity.quarantine': 'federationIdentityQuarantine',
  'federation.identity.repin': 'federationIdentityRepin',
  'federation.peer.retry': 'federationPeerRetry',
  'federation.peer.retry-bulk': 'federationPeerRetryBulk',
}

function text(value: unknown): string {
  return typeof value === 'string' || typeof value === 'number' ? String(value) : ''
}

/**
 * The limit an entry is about, as its page names it: a setting by its
 * section and field (`user.setting`), else a rate limit by its key.
 */
function limitName(e: AdminActivityEntry, t: TFunction): string {
  const field = text(e.payload.field)
  const section = text(e.payload.section) as SettingSection
  if (e.action === 'user.setting') return field && section in SETTING_LABELS ? t(`${SETTING_LABELS[section]}.${field}`) : text(e.payload.key)
  return text(e.payload.key) ? t(`admin.rateLimits.limit.${text(e.payload.key)}`) : ''
}

/**
 * One audit row as a sentence, naming accounts by username: the live one;
 * once the account is deleted, the at-action-time snapshot in the payload
 * (`username`).
 */
export function activitySentence(e: AdminActivityEntry, t: TFunction): string {
  const admin =
    e.adminUserId === SYSTEM_ADMIN ? t('admin.activity.system') : (e.adminUsername ?? t('admin.activity.deletedUser'))
  const target = e.targetUsername ?? (text(e.payload.username) || t('admin.activity.deletedUser'))
  const key = ACTION_KEYS[e.action]
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
  }
  if (key === 'rateLimitUpdate' && values.value === '') return t('admin.activity.actions.rateLimitReset', values)
  if (key === 'userRateLimitUpdate' && values.value === '') return t('admin.activity.actions.userRateLimitReset', values)
  if (key === 'userSettingUpdate' && values.value === '') return t('admin.activity.actions.userSettingReset', values)
  return key ? t(`admin.activity.actions.${key}`, values) : t('admin.activity.actions.unknown', values)
}
