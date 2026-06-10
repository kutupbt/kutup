import { useEffect, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Loader2 } from 'lucide-react'
import { MobileShell } from '@/components/mobile/MobileShell'
import { MobilePageHeader } from '@/components/mobile/MobilePageHeader'
import { Icon, ICONS } from '@/components/mobile/Icon'
import { Surface } from '@/components/ui/surface'
import { PressableRow } from '@/components/ui/pressable-row'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { Input } from '@/components/ui/input'
import { StatusPill } from '@/components/mobile/admin/StatusPill'
import { RolePill } from '@/components/mobile/admin/RolePill'
import { avatarColor, initials } from '@/components/mobile/admin/avatar'
import { formatBytes } from '@/lib/format'
import { useAdminUsers, useUpdateUser, useDeleteUser, useForceDisable2fa } from '@/api/hooks/useAdmin'
import { useIsMobile } from '@/hooks/useIsMobile'
import { cn } from '@/lib/utils'
import type { ReactNode } from 'react'

/**
 * MobileAdminUserDetailPage — `/drive/account/admin/users/:id`.
 *
 * Per the design + the user's "tap → full page, never a slide-in" rule.
 * Every action is wired end-to-end (CLAUDE.md "no silent stubs"):
 *
 *   1. Header card     — avatar + email + role/break-glass pill + status + storage bar
 *   2. Account info    — 2FA / Role / Joined
 *   3. Manage          — Edit quota · Make/Remove admin · Disable 2FA
 *   4. Account state   — Disable / Re-enable · Delete
 *
 * The break-glass admin (`user.isProtected`) can't be demoted, disabled,
 * or deleted — those rows render disabled with a reason (the backend
 * rejects the mutations with 403). Reset password is still out (E2EE
 * design problem — see docs/roadmap.md).
 *
 * Desktop hits redirect to /admin (via useIsMobile-guarded effect).
 */

export default function MobileAdminUserDetailPage() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const { id } = useParams<{ id: string }>()
  const isMobile = useIsMobile()

  useEffect(() => {
    if (!isMobile) navigate('/admin', { replace: true })
  }, [isMobile, navigate])

  const { data: users, isLoading } = useAdminUsers()
  const updateUser = useUpdateUser()
  const deleteUser = useDeleteUser()
  const forceDisable2fa = useForceDisable2fa()
  const user = users?.find((u) => u.id === id)

  const [editQuotaOpen, setEditQuotaOpen] = useState(false)
  const [quotaGB, setQuotaGB] = useState('')
  const [disableConfirmOpen, setDisableConfirmOpen] = useState(false)
  const [deleteConfirmOpen, setDeleteConfirmOpen] = useState(false)
  const [adminConfirmOpen, setAdminConfirmOpen] = useState(false)
  const [totpConfirmOpen, setTotpConfirmOpen] = useState(false)

  // Sync quota input when the user changes.
  useEffect(() => {
    if (user) setQuotaGB(String(Math.round(user.storageQuotaBytes / 1024 / 1024 / 1024)))
  }, [user])

  if (!isMobile) return null

  if (isLoading) {
    return (
      <MobileShell>
        <MobilePageHeader title={t('mobile.admin.user.title', 'User')} back onBack={() => navigate('/drive/account/admin')} />
        <div className="flex justify-center py-10">
          <Loader2 className="h-5 w-5 animate-spin text-text-tertiary" />
        </div>
      </MobileShell>
    )
  }

  if (!user) {
    return (
      <MobileShell>
        <MobilePageHeader title={t('mobile.admin.user.title', 'User')} back onBack={() => navigate('/drive/account/admin')} />
        <div className="px-4 py-10 text-center text-sm text-text-tertiary">
          {t('mobile.admin.user.notFound', 'User not found.')}
        </div>
      </MobileShell>
    )
  }

  const handle = user.username || user.email
  const pct = user.storageQuotaBytes > 0
    ? Math.min((user.storageUsedBytes / user.storageQuotaBytes) * 100, 100)
    : 0
  const over75 = pct > 75

  async function handleSaveQuota() {
    if (!user) return
    const n = parseFloat(quotaGB)
    if (isNaN(n) || n <= 0) return
    await updateUser.mutateAsync({
      id: user.id,
      body: { storageQuotaBytes: n * 1024 * 1024 * 1024 },
    })
    setEditQuotaOpen(false)
    toast.success(t('mobile.admin.user.quotaSaved', 'Quota updated'))
  }

  async function handleToggleStatus() {
    if (!user) return
    await updateUser.mutateAsync({ id: user.id, body: { isActive: !user.isActive } })
    setDisableConfirmOpen(false)
    toast.success(
      user.isActive
        ? t('mobile.admin.user.disabledToast', 'User disabled')
        : t('mobile.admin.user.enabledToast', 'User re-enabled'),
    )
  }

  async function handleDelete() {
    if (!user) return
    await deleteUser.mutateAsync(user.id)
    setDeleteConfirmOpen(false)
    navigate('/drive/account/admin', { replace: true })
  }

  async function handleToggleAdmin() {
    if (!user) return
    await updateUser.mutateAsync({ id: user.id, body: { isAdmin: !user.isAdmin } })
    setAdminConfirmOpen(false)
    toast.success(
      user.isAdmin
        ? t('mobile.admin.user.adminRemovedToast', 'Admin role removed')
        : t('mobile.admin.user.adminGrantedToast', 'User is now an admin'),
    )
  }

  async function handleForceDisable2fa() {
    if (!user) return
    await forceDisable2fa.mutateAsync(user.id)
    setTotpConfirmOpen(false)
  }

  const protectedReason = user.isProtected
    ? t('mobile.admin.user.breakGlassReason', 'Break-glass admin — protected')
    : undefined

  return (
    <MobileShell>
      <MobilePageHeader
        title={t('mobile.admin.user.title', 'User')}
        back
        onBack={() => navigate('/drive/account/admin')}
      />
      <div className="flex-1 overflow-auto px-3.5 pt-4 pb-24">
        {/* Header card */}
        <div className="p-4 bg-surface border border-border-light rounded-[var(--radius-lg)] mb-4">
          <div className="flex items-center gap-3">
            <div
              className="w-14 h-14 rounded-full flex items-center justify-center text-white text-[18px] font-bold shrink-0"
              style={{ background: avatarColor(handle) }}
              aria-hidden="true"
            >
              {initials(handle)}
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-1.5 flex-wrap">
                <span className="text-[15.5px] font-semibold text-text-primary truncate">
                  {user.email}
                </span>
                <RolePill isAdmin={user.isAdmin} />
                {user.isProtected && (
                  <span className="text-[10px] font-bold tracking-[0.04em] uppercase bg-warning-faint text-warning px-1.5 py-0.5 rounded-md">
                    {t('admin.breakGlass.badge', 'Break-glass')}
                  </span>
                )}
              </div>
              <div className="text-[12.5px] text-text-tertiary mt-0.5">
                @{user.username}
              </div>
              <div className="mt-2">
                <StatusPill active={user.isActive} />
              </div>
            </div>
          </div>

          {/* Storage */}
          <div className="mt-4">
            <div className="flex justify-between text-[12px] mb-1.5">
              <span className="text-text-secondary font-medium">
                {t('mobile.admin.user.storage', 'Storage')}
              </span>
              <span className="text-text-tertiary">
                {formatBytes(user.storageUsedBytes)} /{' '}
                {formatBytes(user.storageQuotaBytes)}
              </span>
            </div>
            <div className="h-1.5 bg-surface-sunken rounded-[3px] overflow-hidden">
              <div
                className={cn(
                  'h-full rounded-[3px] transition-all duration-300',
                  over75 ? 'bg-[oklch(0.62_0.16_65)]' : 'bg-primary',
                )}
                style={{ width: `${Math.max(pct, 2)}%` }}
              />
            </div>
          </div>
        </div>

        {/* Account info */}
        <div className="text-[11.5px] font-semibold tracking-[0.06em] uppercase text-text-tertiary px-1 pb-2">
          {t('mobile.admin.user.accountSection', 'Account')}
        </div>
        <Surface className="mb-4.5">
          {[
            {
              label: t('mobile.admin.user.totp', '2FA'),
              value: user.totpEnabled
                ? t('mobile.admin.user.totpEnabled', 'Enabled')
                : t('mobile.admin.user.totpNotSet', 'Not set'),
              hint: user.totpEnabled,
            },
            {
              label: t('mobile.admin.user.role', 'Role'),
              value: user.isAdmin
                ? t('mobile.admin.user.roleAdmin', 'Admin')
                : t('mobile.admin.user.roleUser', 'User'),
            },
            {
              label: t('mobile.admin.user.joined', 'Joined'),
              value: new Date(user.createdAt).toLocaleDateString(undefined, {
                month: 'short',
                day: 'numeric',
                year: 'numeric',
              }),
            },
          ].map((row, i, arr) => (
            <div
              key={row.label}
              className={cn(
                'flex items-center justify-between px-3.5 py-3',
                i === arr.length - 1 ? '' : 'border-b border-border-light',
              )}
            >
              <span className="text-[13.5px] text-text-secondary">{row.label}</span>
              <span
                className={cn(
                  'text-[13.5px] font-medium',
                  row.hint ? 'text-success' : 'text-text-primary',
                )}
              >
                {row.value}
              </span>
            </div>
          ))}
        </Surface>

        {/* Manage */}
        <div className="text-[11.5px] font-semibold tracking-[0.06em] uppercase text-text-tertiary px-1 pb-2">
          {t('mobile.admin.user.manageSection', 'Manage')}
        </div>
        <Surface className="mb-4.5">
          <PressableRow
            onClick={() => setEditQuotaOpen(true)}
            ariaLabel={t('mobile.admin.user.editQuota', 'Edit quota')}
          >
            <div className="w-[30px] h-[30px] rounded-[9px] bg-surface-sunken text-text-secondary flex items-center justify-center shrink-0">
              <Icon d={ICONS.edit} size={15} />
            </div>
            <div className="flex-1 min-w-0">
              <div className="text-[13.5px] font-medium text-text-primary">
                {t('mobile.admin.user.editQuota', 'Edit quota')}
              </div>
              <div className="text-[11.5px] text-text-tertiary mt-0.5">
                {t('mobile.admin.user.currentlyX', 'Currently {{x}}', {
                  x: formatBytes(user.storageQuotaBytes),
                })}
              </div>
            </div>
            <Icon d={ICONS.chevronRight} size={16} color="var(--text-tertiary)" />
          </PressableRow>

          {/* Make / Remove admin — demoting is blocked for the break-glass admin */}
          {user.isProtected && user.isAdmin ? (
            <StaticRow
              icon={ICONS.user}
              label={t('mobile.admin.user.removeAdmin', 'Remove admin role')}
              sub={protectedReason}
            />
          ) : (
            <PressableRow onClick={() => setAdminConfirmOpen(true)}>
              <div className="w-[30px] h-[30px] rounded-[9px] bg-surface-sunken text-text-secondary flex items-center justify-center shrink-0">
                <Icon d={user.isAdmin ? ICONS.user : ICONS.shield} size={15} />
              </div>
              <div className="flex-1 min-w-0">
                <div className="text-[13.5px] font-medium text-text-primary">
                  {user.isAdmin
                    ? t('mobile.admin.user.removeAdmin', 'Remove admin role')
                    : t('mobile.admin.user.makeAdmin', 'Make admin')}
                </div>
                <div className="text-[11.5px] text-text-tertiary mt-0.5">
                  {user.isAdmin
                    ? t('mobile.admin.user.removeAdminSub', 'Revoke access to the admin panel')
                    : t('mobile.admin.user.makeAdminSub', 'Grant full access to the admin panel')}
                </div>
              </div>
              <Icon d={ICONS.chevronRight} size={16} color="var(--text-tertiary)" />
            </PressableRow>
          )}

          {/* Force-disable 2FA — allowed even on the break-glass admin */}
          {user.totpEnabled ? (
            <PressableRow onClick={() => setTotpConfirmOpen(true)} last>
              <div className="w-[30px] h-[30px] rounded-[9px] bg-surface-sunken text-text-secondary flex items-center justify-center shrink-0">
                <Icon d={ICONS.key} size={15} />
              </div>
              <div className="flex-1 min-w-0">
                <div className="text-[13.5px] font-medium text-text-primary">
                  {t('mobile.admin.user.disableTotp', 'Disable 2FA')}
                </div>
                <div className="text-[11.5px] text-text-tertiary mt-0.5">
                  {t('mobile.admin.user.disableTotpSub', 'For users locked out of their authenticator')}
                </div>
              </div>
              <Icon d={ICONS.chevronRight} size={16} color="var(--text-tertiary)" />
            </PressableRow>
          ) : (
            <StaticRow
              icon={ICONS.key}
              label={t('mobile.admin.user.disableTotp', 'Disable 2FA')}
              sub={t('mobile.admin.user.totpAlreadyOff', '2FA is not enabled for this user')}
              last
            />
          )}
        </Surface>

        {/* Account state */}
        <div className="text-[11.5px] font-semibold tracking-[0.06em] uppercase text-text-tertiary px-1 pb-2">
          {t('mobile.admin.user.stateSection', 'Account state')}
        </div>
        <Surface>
          {user.isProtected ? (
            <StaticRow
              icon={ICONS.userX}
              label={t('mobile.admin.user.disable', 'Disable account')}
              sub={protectedReason}
            />
          ) : (
            <PressableRow onClick={() => setDisableConfirmOpen(true)}>
              <div
                className={cn(
                  'w-[30px] h-[30px] rounded-[9px] flex items-center justify-center shrink-0',
                  user.isActive
                    ? 'bg-destructive-faint text-destructive'
                    : 'bg-success-faint text-success',
                )}
              >
                <Icon d={user.isActive ? ICONS.userX : ICONS.userCheck} size={15} />
              </div>
              <div className="flex-1 min-w-0">
                <div
                  className={cn(
                    'text-[13.5px] font-medium',
                    user.isActive ? 'text-destructive' : 'text-text-primary',
                  )}
                >
                  {user.isActive
                    ? t('mobile.admin.user.disable', 'Disable account')
                    : t('mobile.admin.user.enable', 'Re-enable account')}
                </div>
                <div className="text-[11.5px] text-text-tertiary mt-0.5">
                  {user.isActive
                    ? t('mobile.admin.user.disableSub', 'User cannot sign in but data is preserved')
                    : t('mobile.admin.user.enableSub', 'User can sign in again')}
                </div>
              </div>
              <Icon d={ICONS.chevronRight} size={16} color={user.isActive ? 'var(--destructive)' : 'var(--success)'} />
            </PressableRow>
          )}
          {user.isProtected ? (
            <StaticRow
              icon={ICONS.trash}
              label={t('mobile.admin.user.delete', 'Delete permanently')}
              sub={protectedReason}
              last
            />
          ) : (
            <PressableRow onClick={() => setDeleteConfirmOpen(true)} last>
              <div className="w-[30px] h-[30px] rounded-[9px] bg-destructive-faint text-destructive flex items-center justify-center shrink-0">
                <Icon d={ICONS.trash} size={15} />
              </div>
              <div className="flex-1 min-w-0">
                <div className="text-[13.5px] font-medium text-destructive">
                  {t('mobile.admin.user.delete', 'Delete permanently')}
                </div>
                <div className="text-[11.5px] text-text-tertiary mt-0.5">
                  {t('mobile.admin.user.deleteSub', 'All encrypted blobs will be removed')}
                </div>
              </div>
              <Icon d={ICONS.chevronRight} size={16} color="var(--destructive)" />
            </PressableRow>
          )}
        </Surface>
      </div>

      {/* Edit quota dialog */}
      <AlertDialog open={editQuotaOpen} onOpenChange={setEditQuotaOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('mobile.admin.user.editQuota', 'Edit quota')}</AlertDialogTitle>
            <AlertDialogDescription>
              {t(
                'mobile.admin.user.editQuotaDesc',
                'Set the storage quota in gigabytes. Existing files are preserved.',
              )}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <Input
            type="number"
            inputMode="decimal"
            min="0"
            step="1"
            value={quotaGB}
            onChange={(e) => setQuotaGB(e.target.value)}
            className="my-2"
            aria-label={t('mobile.admin.user.quotaGB', 'Quota (GB)')}
          />
          <AlertDialogFooter>
            <AlertDialogCancel>{t('common.cancel')}</AlertDialogCancel>
            <AlertDialogAction onClick={handleSaveQuota}>
              {t('common.save', 'Save')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Disable / Re-enable confirm */}
      <AlertDialog open={disableConfirmOpen} onOpenChange={setDisableConfirmOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              {user.isActive
                ? t('mobile.admin.user.disableTitle', 'Disable {{email}}?', { email: user.email })
                : t('mobile.admin.user.enableTitle', 'Re-enable {{email}}?', { email: user.email })}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {user.isActive
                ? t('mobile.admin.user.disableSub', 'User cannot sign in but data is preserved')
                : t('mobile.admin.user.enableSub', 'User can sign in again')}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('common.cancel')}</AlertDialogCancel>
            <AlertDialogAction
              className={user.isActive ? 'bg-destructive text-destructive-foreground hover:bg-destructive/90' : ''}
              onClick={handleToggleStatus}
            >
              {user.isActive
                ? t('mobile.admin.user.disable', 'Disable account')
                : t('mobile.admin.user.enable', 'Re-enable account')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Delete confirm */}
      <AlertDialog open={deleteConfirmOpen} onOpenChange={setDeleteConfirmOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              {t('mobile.admin.user.deleteTitle', 'Delete {{email}}?', { email: user.email })}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {t(
                'mobile.admin.user.deleteDesc',
                'All encrypted blobs will be removed. This cannot be undone.',
              )}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('common.cancel')}</AlertDialogCancel>
            <AlertDialogAction
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
              onClick={handleDelete}
            >
              {t('mobile.admin.user.delete', 'Delete permanently')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Promote / demote confirm */}
      <AlertDialog open={adminConfirmOpen} onOpenChange={setAdminConfirmOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              {user.isAdmin
                ? t('mobile.admin.user.demoteTitle', 'Remove admin from {{email}}?', { email: user.email })
                : t('mobile.admin.user.promoteTitle', 'Make {{email}} an admin?', { email: user.email })}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {user.isAdmin
                ? t('mobile.admin.user.demoteDesc', 'They lose access to the admin panel. Takes effect on their next sign-in.')
                : t('mobile.admin.user.promoteDesc', 'They gain full access to the admin panel. Takes effect on their next sign-in.')}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('common.cancel')}</AlertDialogCancel>
            <AlertDialogAction onClick={handleToggleAdmin}>
              {user.isAdmin
                ? t('mobile.admin.user.removeAdmin', 'Remove admin role')
                : t('mobile.admin.user.makeAdmin', 'Make admin')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Force-disable 2FA confirm */}
      <AlertDialog open={totpConfirmOpen} onOpenChange={setTotpConfirmOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              {t('mobile.admin.user.totpTitle', 'Disable 2FA for {{email}}?', { email: user.email })}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {t(
                'mobile.admin.user.totpDesc',
                'The account becomes password-only until the user re-enables 2FA from their Security page.',
              )}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('common.cancel')}</AlertDialogCancel>
            <AlertDialogAction onClick={handleForceDisable2fa}>
              {t('mobile.admin.user.disableTotp', 'Disable 2FA')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </MobileShell>
  )
}

/**
 * StaticRow — a non-interactive list row, used for actions that are
 * unavailable on this user (e.g. demote/disable/delete on the break-glass
 * admin). Muted styling + a reason in the sub-line; no tap feedback.
 */
function StaticRow({
  icon,
  label,
  sub,
  last,
}: {
  icon: string
  label: string
  sub?: ReactNode
  last?: boolean
}) {
  return (
    <div
      className={cn(
        'flex items-center gap-3 px-3.5 py-3 opacity-55 select-none',
        last ? 'border-b-0' : 'border-b border-border-light',
      )}
    >
      <div className="w-[30px] h-[30px] rounded-[9px] bg-surface-sunken text-text-tertiary flex items-center justify-center shrink-0">
        <Icon d={icon} size={15} />
      </div>
      <div className="flex-1 min-w-0">
        <div className="text-[13.5px] font-medium text-text-secondary">{label}</div>
        {sub && <div className="text-[11.5px] text-text-tertiary mt-0.5">{sub}</div>}
      </div>
    </div>
  )
}
