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
 * Per-action wiring decisions (same as mobile admin):
 *  - **Edit quota** — opens a small dialog wired to `useUpdateUser`.
 *  - **Reset password** — STUB. No backend endpoint yet (PR 13.1).
 *  - **Toggle 2FA** — STUB. No backend endpoint to force/disable TOTP yet.
 *  - **Make / Remove admin** — STUB. `PUT /admin/users/:id` body doesn't
 *    accept `isAdmin` today; wire when the backend slice lands (PR 13.1).
 *  - **Disable / Re-enable** — wired via `useUpdateUser({ isActive })`.
 *  - **Delete permanently** — wired via `useDeleteUser` after AlertDialog confirm.
 */

export type AdminMenuAction =
  | 'editQuota'
  | 'resetPassword'
  | 'toggleTotp'
  | 'toggleAdmin'
  | 'toggleActive'
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

  const groups: MenuItem[][] = [
    [
      { id: 'editQuota', icon: 'edit', label: t('admin.users.menu.editQuota', 'Edit quota') },
      { id: 'resetPassword', icon: 'refresh', label: t('admin.users.menu.resetPassword', 'Reset password') },
      {
        id: 'toggleTotp',
        icon: 'key',
        label: u.totpEnabled
          ? t('admin.users.menu.disableTotp', 'Disable 2FA')
          : t('admin.users.menu.requireTotp', 'Require 2FA'),
      },
    ],
    [
      {
        id: 'toggleAdmin',
        icon: u.isAdmin ? 'user' : 'shield',
        label: u.isAdmin
          ? t('admin.users.menu.removeAdmin', 'Remove admin role')
          : t('admin.users.menu.makeAdmin', 'Make admin'),
      },
      {
        id: 'toggleActive',
        icon: u.isActive ? 'userX' : 'userCheck',
        label: u.isActive
          ? t('admin.users.menu.disable', 'Disable account')
          : t('admin.users.menu.reenable', 'Re-enable account'),
        danger: u.isActive,
      },
    ],
    [
      {
        id: 'delete',
        icon: 'trash',
        label: t('admin.users.menu.delete', 'Delete permanently'),
        danger: true,
      },
    ],
  ]

  // Clamp coords so the menu can't render off-screen. Width ~220, height ~340.
  const x = Math.min(menu.x, window.innerWidth - 230)
  const y = Math.min(menu.y, window.innerHeight - 340)

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
          {group.map((item) => (
            <button
              key={item.id}
              role="menuitem"
              onClick={() => {
                onAction(item.id, u)
                onClose()
              }}
              className={cn(
                'flex items-center gap-2.5 w-full px-3.5 py-1.5 border-0 cursor-pointer text-left bg-transparent',
                'text-[13px] font-medium',
                item.danger
                  ? 'text-destructive hover:bg-destructive-faint'
                  : 'text-text-primary hover:bg-surface-raised',
              )}
            >
              <Icon d={ICONS[item.icon]} size={13} />
              {item.label}
            </button>
          ))}
        </div>
      ))}
    </div>
  )
}
