import { useEffect, useRef } from 'react'
import { useTranslation } from 'react-i18next'
import { Icon, ICONS, type IconName } from '@/components/mobile/Icon'
import { cn } from '@/lib/utils'
import type { UserRow } from '@/types/api'

/**
 * AdminUserMenu — per-row ⋯ context menu on the desktop admin Users table.
 *
 * Positioned-popover pattern: parent passes `(x, y)` from the click event;
 * the menu clamps itself to the viewport so it never clips off-screen.
 * Click-outside / Escape both close the menu.
 *
 * Every action here is wired end-to-end — no silent stubs per the CLAUDE.md
 * "pre-production, not pre-quality" rule.
 *
 *  - **Edit quota** — opens a small dialog wired to `useUpdateUser`.
 *  - **Make / Remove admin** — `useUpdateUser({ isAdmin })`.
 *  - **Disable 2FA** — `useForceDisable2fa` (admin override for lockouts).
 *  - **Disable / Re-enable** — `useUpdateUser({ isActive })`.
 *  - **Delete permanently** — `useDeleteUser` after an AlertDialog confirm.
 *
 * For the break-glass admin (`user.isProtected`), the demote / disable /
 * delete items render disabled with an explanation — the backend rejects
 * those mutations with 403, so the UI surfaces the reason up front.
 */

export type AdminMenuAction =
  | 'editQuota'
  | 'toggleAdmin'
  | 'disableTotp'
  | 'rotateTempPassword'
  | 'toggleActive'
  | 'wipe'
  | 'delete'

export interface AdminUserMenuState {
  x: number
  y: number
  user: UserRow
}

interface AdminUserMenuProps {
  menu: AdminUserMenuState | null
  onClose: () => void
  onAction: (action: AdminMenuAction, user: UserRow) => void
}

interface MenuItem {
  id: AdminMenuAction
  icon: IconName
  label: string
  danger?: boolean
  /** Disabled with a reason (e.g. break-glass admin protection). */
  disabledReason?: string
}

export function AdminUserMenu({ menu, onClose, onAction }: AdminUserMenuProps) {
  const { t } = useTranslation()
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!menu) return
    function onDocClick(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) onClose()
    }
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape') onClose()
    }
    document.addEventListener('mousedown', onDocClick)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onDocClick)
      document.removeEventListener('keydown', onKey)
    }
  }, [menu, onClose])

  if (!menu) return null

  const u = menu.user
  // The break-glass admin can't be demoted / disabled / deleted.
  const protectedReason = u.isProtected
    ? t('admin.users.menu.breakGlassReason', 'Break-glass admin — protected')
    : undefined

  const groups: MenuItem[][] = [
    [
      { id: 'editQuota', icon: 'edit', label: t('admin.users.menu.editQuota', 'Edit quota') },
      {
        id: 'toggleAdmin',
        icon: u.isAdmin ? 'user' : 'shield',
        label: u.isAdmin
          ? t('admin.users.menu.removeAdmin', 'Remove admin role')
          : t('admin.users.menu.makeAdmin', 'Make admin'),
        // Demoting an admin is the protected direction; promoting is fine.
        disabledReason: u.isAdmin ? protectedReason : undefined,
      },
      {
        id: 'disableTotp',
        icon: 'key',
        label: t('admin.users.menu.disableTotp', 'Disable 2FA'),
        // 2FA disable is allowed even on the break-glass admin.
        disabledReason: u.totpEnabled
          ? undefined
          : t('admin.users.menu.totpAlreadyOff', '2FA is not enabled'),
      },
      {
        id: 'rotateTempPassword',
        icon: 'refresh',
        label: t('admin.users.menu.rotateTempPassword', 'Rotate temp password'),
        // Only safe while the account has no key material (first-login state).
        // Established accounts self-serve via their recovery phrase.
        disabledReason: u.isFirstLogin
          ? undefined
          : t(
              'admin.users.menu.rotateTempPasswordDisabled',
              'Setup completed — only the user can reset their password (recovery phrase)',
            ),
      },
    ],
    [
      {
        id: 'toggleActive',
        icon: u.isActive ? 'userX' : 'userCheck',
        label: u.isActive
          ? t('admin.users.menu.disable', 'Disable account')
          : t('admin.users.menu.reenable', 'Re-enable account'),
        danger: u.isActive,
        disabledReason: u.isActive ? protectedReason : undefined,
      },
    ],
    [
      {
        id: 'wipe',
        icon: 'alertTriangle',
        label: t('admin.users.menu.wipe', 'Wipe account…'),
        danger: true,
        disabledReason: protectedReason,
      },
      {
        id: 'delete',
        icon: 'trash',
        label: t('admin.users.menu.delete', 'Delete permanently'),
        danger: true,
        disabledReason: protectedReason,
      },
    ],
  ]

  // Clamp coords so the menu can't render off-screen. Width ~220, height ~260.
  const x = Math.min(menu.x, window.innerWidth - 230)
  const y = Math.min(menu.y, window.innerHeight - 280)

  return (
    <div
      ref={ref}
      role="menu"
      style={{ left: x, top: y }}
      className="fixed z-50 min-w-[210px] bg-surface border border-border rounded-[var(--radius-lg)] shadow-[var(--shadow-lg)] py-1"
    >
      {groups.map((group, gi) => (
        <div key={gi}>
          {gi > 0 && <div className="h-px bg-border-light my-1" aria-hidden="true" />}
          {group.map((item) => {
            const disabled = item.disabledReason != null
            return (
              <button
                key={item.id}
                role="menuitem"
                disabled={disabled}
                title={item.disabledReason}
                onClick={() => {
                  if (disabled) return
                  onAction(item.id, u)
                  onClose()
                }}
                className={cn(
                  'flex items-center gap-2.5 w-full px-3.5 py-1.5 border-0 text-left bg-transparent',
                  'text-[13px] font-medium',
                  disabled
                    ? 'text-text-tertiary cursor-not-allowed'
                    : item.danger
                      ? 'text-destructive hover:bg-destructive-faint cursor-pointer'
                      : 'text-text-primary hover:bg-surface-raised cursor-pointer',
                )}
              >
                <Icon d={ICONS[item.icon]} size={13} />
                <span className="flex-1">{item.label}</span>
              </button>
            )
          })}
        </div>
      ))}
    </div>
  )
}
