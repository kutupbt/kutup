import type { TFunction } from 'i18next'
import { ICONS } from '@/components/mobile/Icon'
import type { AdminActivityEntry } from '@/types/api'

/**
 * Shared rendering helpers for the admin audit-log feed (desktop
 * AdminOverviewTab + MobileAdminOverviewTab).
 *
 * The target's display name prefers the LIVE email from the join; once the
 * account is deleted it falls back to the at-action-time snapshot the backend
 * stores in `payload.email`.
 */

export function activityTarget(e: AdminActivityEntry, t: TFunction): string {
  return (
    e.targetEmail ??
    (typeof e.payload.email === 'string' ? e.payload.email : null) ??
    t('admin.activity.deletedUser', 'deleted user')
  )
}

export function activityAdmin(e: AdminActivityEntry, t: TFunction): string {
  if (e.adminUserId === '00000000-0000-0000-0000-000000000000') {
    return t('admin.activity.systemOperator', 'system/operator')
  }
  return e.adminEmail ?? t('admin.activity.deletedUser', 'deleted user')
}

export function activityText(e: AdminActivityEntry, t: TFunction): string {
  const admin = activityAdmin(e, t)
  const target = activityTarget(e, t)
  switch (e.action) {
    case 'user.create':
      return t('admin.activity.action.userCreate', '{{admin}} created user {{target}}', {
        admin,
        target,
      })
    case 'user.update':
      return t('admin.activity.action.userUpdate', '{{admin}} updated {{target}}', {
        admin,
        target,
      })
    case 'user.delete':
      return t('admin.activity.action.userDelete', '{{admin}} deleted user {{target}}', {
        admin,
        target,
      })
    case 'user.2fa_disable':
      return t('admin.activity.action.user2faDisable', '{{admin}} disabled 2FA for {{target}}', {
        admin,
        target,
      })
    case 'user.rotate_temp_password':
      return t(
        'admin.activity.action.userRotateTempPassword',
        '{{admin}} rotated the temp password of {{target}}',
        { admin, target },
      )
    case 'user.wipe':
      return t('admin.activity.action.userWipe', '{{admin}} wiped {{target}}', {
        admin,
        target,
      })
    case 'settings.update':
      return t('admin.activity.action.settingsUpdate', '{{admin}} updated server settings', {
        admin,
      })
    case 'federation.policy.update':
      return t(
        'admin.activity.action.federationPolicyUpdate',
        '{{admin}} changed {{feature}} federation mode to {{mode}}',
        {
          admin,
          feature: String(e.payload.feature ?? 'feature'),
          mode: String(e.payload.mode ?? ''),
        },
      )
    case 'federation.rule.upsert':
      return t(
        'admin.activity.action.federationRuleUpsert',
        '{{admin}} updated the federation rule for {{domain}}',
        { admin, domain: String(e.payload.domain ?? '') },
      )
    case 'federation.identity.genesis':
      return t('admin.activity.action.federationIdentityGenesis', '{{admin}} created the local federation identity', { admin })
    case 'federation.identity.rotate-local':
      return t('admin.activity.action.federationIdentityRotateLocal', '{{admin}} rotated the local federation identity', { admin })
    case 'federation.identity.pin':
      return t('admin.activity.action.federationIdentityPin', '{{admin}} pinned {{domain}} by TOFU', { admin, domain: String(e.payload.domain ?? '') })
    case 'federation.identity.verify':
      return t('admin.activity.action.federationIdentityVerify', '{{admin}} verified {{domain}}', { admin, domain: String(e.payload.domain ?? '') })
    case 'federation.identity.advance-remote':
      return t('admin.activity.action.federationIdentityAdvance', '{{admin}} accepted an authenticated rotation for {{domain}}', { admin, domain: String(e.payload.domain ?? '') })
    case 'federation.identity.quarantine':
      return t('admin.activity.action.federationIdentityQuarantine', '{{admin}} quarantined {{domain}}', { admin, domain: String(e.payload.domain ?? '') })
    case 'federation.identity.repin':
      return t('admin.activity.action.federationIdentityRepin', '{{admin}} break-glass re-pinned {{domain}}', { admin, domain: String(e.payload.domain ?? '') })
    case 'federation.peer.retry':
      return t('admin.activity.action.federationPeerRetry', '{{admin}} retried discovery for {{domain}}', { admin, domain: String(e.payload.domain ?? '') })
    case 'federation.peer.retry-bulk':
      return t('admin.activity.action.federationPeerRetryBulk', '{{admin}} retried discovery for multiple peers', { admin })
    case 'federation.rule.delete':
      return t(
        'admin.activity.action.federationRuleDelete',
        '{{admin}} removed the federation rule for {{domain}}',
        { admin, domain: String(e.payload.domain ?? '') },
      )
    default:
      return t('admin.activity.action.unknown', '{{admin}}: {{action}}', {
        admin,
        action: e.action,
      })
  }
}

/** Compact structured evidence kept visible beside security-sensitive events. */
export function activityDetails(e: AdminActivityEntry): string[] {
  const details: string[] = []
  const add = (label: string, key: string) => {
    const value = e.payload[key]
    if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
      details.push(`${label}: ${String(value)}`)
    }
  }
  add('feature', 'feature')
  add('domain', 'domain')
  add('sequence', 'sequence')
  add('previous sequence', 'previousSequence')
  add('candidate sequence', 'candidateSequence')
  add('new sequence', 'newSequence')
  add('fingerprint', 'fingerprint')
  add('old fingerprint', 'oldFingerprint')
  add('new fingerprint', 'newFingerprint')
  add('retained fingerprint', 'retainedFingerprint')
  add('candidate fingerprint', 'candidateFingerprint')
  add('reason', 'reason')
  add('refreshed', 'refreshed')
  add('error', 'error')
  if (Array.isArray(e.payload.results)) {
    for (const result of e.payload.results) {
      if (!result || typeof result !== 'object') continue
      const item = result as Record<string, unknown>
      const domain = typeof item.domain === 'string' ? item.domain : 'unknown peer'
      const refreshed = item.refreshed === true ? 'refreshed' : 'failed'
      const error = typeof item.error === 'string' && item.error ? ` · ${item.error}` : ''
      details.push(`retry ${domain}: ${refreshed}${error}`)
    }
  }
  return details
}

/** Icon path (from `ICONS`) per action kind. */
export function activityIcon(action: string): string {
  switch (action) {
    case 'user.create':
      return ICONS.userPlus
    case 'user.delete':
      return ICONS.trash
    case 'user.rotate_temp_password':
      return ICONS.refresh
    case 'user.wipe':
      return ICONS.alertTriangle
    case 'user.2fa_disable':
      return ICONS.shield
    case 'settings.update':
      return ICONS.settings
    case 'federation.policy.update':
    case 'federation.rule.upsert':
    case 'federation.rule.delete':
      return ICONS.globe
    default:
      return action.startsWith('federation.') ? ICONS.globe : ICONS.userCheck
  }
}
