import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Icon, ICONS } from '@/components/mobile/Icon'
import { StatusPill } from '@/components/mobile/admin/StatusPill'
import { RolePill } from '@/components/mobile/admin/RolePill'
import { avatarColor, initials } from '@/components/mobile/admin/avatar'
import { formatBytes } from '@/lib/format'
import type { UserRow } from '@/types/api'
import { cn } from '@/lib/utils'

/**
 * UserListRow — one row in the Users tab list. Tap → navigates to the user
 * detail page (`/drive/account/admin/users/:id`).
 *
 * Layout (per design):
 *   [Avatar 40×40]  [Email + RolePill / StatusPill + 2FA + quota text]  [▸]
 *                   [-------- mini quota bar (3px tall) -----------]
 *
 * Quota bar turns warning-amber over 75% used. Avatar color is stable per
 * username (see `./avatar.ts`).
 */
interface UserListRowProps {
  user: UserRow
  onOpen: (user: UserRow) => void
  /** Suppress the bottom border on the last row in the surface. */
  last?: boolean
}

export function UserListRow({ user, onOpen, last }: UserListRowProps) {
  const { t } = useTranslation()
  const [pressed, setPressed] = useState(false)
  const pct = user.storageQuotaBytes > 0
    ? Math.min((user.storageUsedBytes / user.storageQuotaBytes) * 100, 100)
    : 0
  const over75 = pct > 75
  const handle = user.username || user.email

  return (
    <div
      role="button"
      tabIndex={0}
      aria-label={t('mobile.admin.users.openRow', 'Open {{email}}', { email: user.email })}
      onClick={() => onOpen(user)}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault()
          onOpen(user)
        }
      }}
      onTouchStart={() => setPressed(true)}
      onTouchEnd={() => setPressed(false)}
      onTouchCancel={() => setPressed(false)}
      onMouseDown={() => setPressed(true)}
      onMouseUp={() => setPressed(false)}
      onMouseLeave={() => setPressed(false)}
      className={cn(
        'flex items-center gap-3 px-3.5 py-3 select-none cursor-pointer transition-colors',
        pressed ? 'bg-surface-raised' : 'bg-transparent',
        last ? 'border-b-0' : 'border-b border-border-light',
      )}
    >
      <div
        className="w-10 h-10 rounded-full flex items-center justify-center text-white text-[13.5px] font-bold shrink-0"
        style={{ background: avatarColor(handle) }}
        aria-hidden="true"
      >
        {initials(handle)}
      </div>

      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-1.5">
          <span className="text-sm font-semibold text-text-primary truncate min-w-0">
            {user.email}
          </span>
          <RolePill isAdmin={user.isAdmin} />
        </div>
        <div className="flex items-center gap-1.5 mt-1 flex-wrap">
          <StatusPill active={user.isActive} />
          {user.totpEnabled && (
            <span className="inline-flex items-center gap-0.5 text-[10.5px] text-text-tertiary font-medium">
              <Icon d={ICONS.key} size={10} />
              2FA
            </span>
          )}
          <span className="text-[11px] text-text-tertiary">·</span>
          <span className="text-[11px] text-text-tertiary">
            {formatBytes(user.storageUsedBytes)} / {formatBytes(user.storageQuotaBytes)}
          </span>
        </div>
        <div className="h-[3px] bg-surface-sunken rounded-[2px] mt-1.5 overflow-hidden">
          <div
            className={cn(
              'h-full rounded-[2px] transition-all duration-300',
              over75 ? 'bg-[oklch(0.62_0.16_65)]' : 'bg-primary',
            )}
            style={{ width: `${Math.max(pct, 2)}%` }}
          />
        </div>
      </div>

      <Icon d={ICONS.chevronRight} size={16} color="var(--text-tertiary)" />
    </div>
  )
}
