import type { AdminActivityEntry } from '@kutup/session/api-types'
import type { useTranslation } from 'react-i18next'

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
  'settings.update': 'settingsUpdate',
  'maps.settings.update': 'mapsSettingsUpdate',
  'mail.sending.update': 'mailSendingUpdate',
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
 * One audit row as a sentence. The target prefers the live email; once the
 * account is deleted, the at-action-time snapshot in `payload.email`.
 */
export function activitySentence(e: AdminActivityEntry, t: TFunction): string {
  const admin =
    e.adminUserId === SYSTEM_ADMIN ? t('admin.activity.system') : (e.adminEmail ?? t('admin.activity.deletedUser'))
  const target = e.targetEmail ?? (text(e.payload.email) || t('admin.activity.deletedUser'))
  const key = ACTION_KEYS[e.action]
  const values = {
    admin,
    target,
    domain: text(e.payload.domain),
    feature: text(e.payload.feature),
    mode: text(e.payload.mode),
    action: e.action,
  }
  return key ? t(`admin.activity.actions.${key}`, values) : t('admin.activity.actions.unknown', values)
}
