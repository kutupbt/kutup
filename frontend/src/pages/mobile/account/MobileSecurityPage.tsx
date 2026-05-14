import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Icon, ICONS } from '@/components/mobile/Icon'
import { MobileAccountSubPage } from '@/pages/mobile/account/MobileAccountSubPage'
import { Surface } from '@/components/ui/surface'
import { PressableRow } from '@/components/ui/pressable-row'
import { EmptyState } from '@/components/ui/empty-state'
import { Button } from '@/components/ui/button'
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
import { useAppDispatch, useAppSelector } from '@/store'
import { updateTotpEnabled } from '@/store/authSlice'
import { listDevices, revokeDevice, type DeviceRow } from '@/api/collab'
import api from '@/api/client'
import { cn } from '@/lib/utils'

/**
 * MobileSecurityPage — `/drive/account/security`.
 *
 * Two sections:
 *  - **Two-factor (TOTP)**: status indicator + Set-up flow (BottomSheet
 *    with QR + secret + 6-digit verify) + Disable confirm (AlertDialog).
 *  - **Trusted devices**: list of `DeviceRow`s with status + last-seen +
 *    Revoke action (AlertDialog confirm per row).
 *
 * Reuses the existing kutup API endpoints (`/user/2fa/setup`,
 * `/user/2fa/verify`, `/user/2fa` DELETE, `listDevices`, `revokeDevice`) so
 * the mobile flow stays in lock-step with desktop Settings.
 */

export default function MobileSecurityPage() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const dispatch = useAppDispatch()
  const auth = useAppSelector((s) => s.auth)
  const totpOn = !!auth.totpEnabled

  // TOTP setup is its own page (`/drive/account/security/totp-setup`),
  // not a bottom sheet — the user needs to switch to their authenticator
  // app to add the key, and a sheet would get dismissed on the
  // background-foreground cycle. A durable URL persists state cleanly.
  const [disableOpen, setDisableOpen] = useState(false)

  async function disableTOTP() {
    try {
      await api.delete('/user/2fa')
      dispatch(updateTotpEnabled(false))
      toast.success(t('settings.totp.disabledToast'))
      setDisableOpen(false)
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { error?: string } } }).response?.data?.error
      toast.error(msg ?? t('settings.totp.disableFailed'))
    }
  }

  // --- Devices state ------------------------------------------------------
  const [devs, setDevs] = useState<DeviceRow[]>([])
  const [devsLoading, setDevsLoading] = useState(true)
  const [devsError, setDevsError] = useState<string | null>(null)
  const [revokeTarget, setRevokeTarget] = useState<DeviceRow | null>(null)

  useEffect(() => {
    void refreshDevices()
    // refreshDevices is stable; eslint-rule disable for the local ref.
  }, [])

  async function refreshDevices() {
    setDevsLoading(true)
    setDevsError(null)
    try {
      const list = await listDevices()
      setDevs(list)
    } catch (e) {
      setDevsError(e instanceof Error ? e.message : 'load failed')
    } finally {
      setDevsLoading(false)
    }
  }

  async function confirmRevoke() {
    if (!revokeTarget) return
    try {
      await revokeDevice(revokeTarget.deviceId)
      setDevs((arr) =>
        arr.map((x) =>
          x.deviceId === revokeTarget.deviceId ? { ...x, isActive: false } : x,
        ),
      )
      toast.success(t('settings.devices.revokedToast'))
    } catch (e) {
      toast.error(
        t('settings.devices.revokeFailed', {
          error: e instanceof Error ? e.message : String(e),
        }),
      )
    } finally {
      setRevokeTarget(null)
    }
  }

  return (
    <MobileAccountSubPage title={t('mobile.account.security', 'Security')}>
      {/* ─── Two-factor ─── */}
      <div className="mb-6">
        <div className="text-[11.5px] font-semibold tracking-[0.06em] uppercase text-text-tertiary px-1 mb-2">
          {t('settings.totp.title', 'Two-Factor Authentication')}
        </div>
        <Surface className="p-4">
          <div className="flex items-start gap-3 mb-3">
            <div
              className={cn(
                'w-10 h-10 rounded-[12px] flex items-center justify-center shrink-0',
                totpOn ? 'bg-success-faint text-success' : 'bg-surface-sunken text-text-secondary',
              )}
              aria-hidden="true"
            >
              <Icon d={ICONS.shield} size={20} />
            </div>
            <div className="flex-1 min-w-0">
              <div className="text-sm font-semibold text-text-primary">
                {t('mobile.account.security.totp', 'Two-factor authentication')}
              </div>
              <div
                className={cn(
                  'text-[12px] mt-0.5',
                  totpOn ? 'text-success' : 'text-text-tertiary',
                )}
              >
                {totpOn
                  ? t('mobile.account.security.totpOn', 'Enabled')
                  : t('mobile.account.security.totpOffDescription', 'Add an extra layer of security with an authenticator app')}
              </div>
            </div>
          </div>
          {totpOn ? (
            <Button
              variant="destructive"
              size="sm"
              className="w-full min-h-tap"
              onClick={() => setDisableOpen(true)}
            >
              {t('settings.totp.disable', 'Disable')}
            </Button>
          ) : (
            <Button
              className="w-full min-h-tap"
              onClick={() => navigate('/drive/account/security/totp-setup')}
            >
              {t('settings.totp.setupButton', 'Set up TOTP')}
            </Button>
          )}
        </Surface>
      </div>

      {/* ─── Trusted devices ─── */}
      <div>
        <div className="text-[11.5px] font-semibold tracking-[0.06em] uppercase text-text-tertiary px-1 mb-2">
          {t('settings.devices.title', 'Trusted devices')}
        </div>
        <p className="text-[12px] text-text-tertiary px-1 mb-2">
          {t('settings.devices.desc')}
        </p>
        {devsLoading ? (
          <div className="text-sm text-text-tertiary py-4 text-center">
            {t('common.loading')}
          </div>
        ) : devsError ? (
          <div className="text-sm text-destructive py-4 text-center">
            {t('settings.devices.errorPrefix')} {devsError}
          </div>
        ) : devs.length === 0 ? (
          <EmptyState
            icon="user"
            title={t('settings.devices.empty', 'No devices yet')}
            subtitle={t('mobile.account.security.devicesEmptyHint', 'Devices appear here when they start a collaborative edit.')}
            tint="muted"
          />
        ) : (
          <Surface>
            {devs.map((d, i) => {
              const label =
                d.label || t('settings.devices.fallbackLabel', { id: d.deviceId })
              return (
                <PressableRow key={d.deviceId} last={i === devs.length - 1}>
                  <div className="w-8 h-8 rounded-[10px] bg-surface-sunken text-text-secondary flex items-center justify-center shrink-0">
                    <Icon d={ICONS.user} size={16} />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="text-sm font-medium text-text-primary truncate">
                      {label}
                    </div>
                    <div className="text-[12px] text-text-tertiary truncate">
                      {d.isActive
                        ? t('settings.devices.active')
                        : t('settings.devices.revoked')}
                      {d.lastSeenAt &&
                        ' · ' +
                          t('settings.devices.lastSeenAt', {
                            when: new Date(d.lastSeenAt).toLocaleDateString(),
                          })}
                    </div>
                  </div>
                  {d.isActive && (
                    <button
                      type="button"
                      onClick={() => setRevokeTarget(d)}
                      className="text-[12px] font-medium text-destructive bg-destructive-faint px-2.5 py-1.5 rounded-[12px] cursor-pointer min-h-tap"
                    >
                      {t('settings.devices.revoke', 'Revoke')}
                    </button>
                  )}
                </PressableRow>
              )
            })}
          </Surface>
        )}
      </div>

      {/* TOTP setup is its own page now (`/drive/account/security/totp-setup`)
          — see BottomSheet's "WHEN TO USE" doc comment for the rationale. */}

      {/* Disable TOTP confirm */}
      <AlertDialog open={disableOpen} onOpenChange={setDisableOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('settings.totp.disableTitle')}</AlertDialogTitle>
            <AlertDialogDescription>{t('settings.totp.disableDesc')}</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('common.cancel')}</AlertDialogCancel>
            <AlertDialogAction
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
              onClick={disableTOTP}
            >
              {t('settings.totp.disableConfirm')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Revoke device confirm */}
      <AlertDialog
        open={revokeTarget !== null}
        onOpenChange={(open) => !open && setRevokeTarget(null)}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('settings.devices.revokeTitle')}</AlertDialogTitle>
            <AlertDialogDescription>
              {t('settings.devices.revokeDesc', {
                label:
                  revokeTarget?.label ||
                  t('settings.devices.fallbackLabel', { id: revokeTarget?.deviceId ?? 0 }),
              })}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('common.cancel')}</AlertDialogCancel>
            <AlertDialogAction
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
              onClick={confirmRevoke}
            >
              {t('settings.devices.revoke')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </MobileAccountSubPage>
  )
}
