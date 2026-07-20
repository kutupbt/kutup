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
        '{{admin}} changed chat federation mode to {{mode}}',
        { admin, mode: String(e.payload.mode ?? '') },
      )
    case 'federation.rule.upsert':
      return t(
        'admin.activity.action.federationRuleUpsert',
        '{{admin}} updated the federation rule for {{domain}}',
        { admin, domain: String(e.payload.domain ?? '') },
      )
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
      return ICONS.userCheck
  }
}
