import { Check, Link2, Loader2, MonitorSmartphone, Pencil, X } from 'lucide-react'
import { useEffect, useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import type { ChatDevice } from '@kutup/chat-core/types'
import { Button } from '@kutup/ui/components/button'
import { Checkbox } from '@kutup/ui/components/checkbox'
import { ConfirmDestructive } from '@kutup/ui/components/confirm-destructive'
import { Input } from '@kutup/ui/components/input'
import { useChat } from '../../app/chatStore'
import { chatErrorMessage } from '../../lib/errors'
import { LinkNewDeviceDialog } from './LinkNewDeviceDialog'
import { SettingsSection } from './SettingsPage'

const POLL_MS = 3_000

function when(value: string | null | undefined, locale: string): string | null {
  if (!value) return null
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? null : date.toLocaleString(locale, { dateStyle: 'medium', timeStyle: 'short' })
}

/**
 * The browsers and apps of this account's Chat, which share its identity
 * (docs/plans/account-identity-key.md). A new one is linked from here;
 * removing one stops messages reaching it (this one cannot be removed from
 * itself), and for a lost or stolen one the identity is reset at the same
 * time, keeping the others. Names are private labels and change no keys.
 */
export function DevicesSettings() {
  const { t, i18n } = useTranslation()
  const { service } = useChat()
  const [devices, setDevices] = useState<ChatDevice[] | null>(null)
  const [editing, setEditing] = useState<number | null>(null)
  const [draft, setDraft] = useState('')
  const [busy, setBusy] = useState(false)
  const [revoking, setRevoking] = useState<ChatDevice | null>(null)
  // A device being removed may be lost or stolen: by default its removal
  // also resets the account identity, which the removed device keeps.
  const [resetIdentity, setResetIdentity] = useState(true)
  const [linking, setLinking] = useState(false)

  useEffect(() => {
    if (!service) return
    let cancelled = false
    const load = (quiet: boolean) =>
      void service
        .devices()
        .then((list) => !cancelled && setDevices(list))
        .catch((error: unknown) => !cancelled && !quiet && toast.error(chatErrorMessage(error, t)))
    load(false)
    const timer = window.setInterval(() => load(true), POLL_MS)
    return () => {
      cancelled = true
      window.clearInterval(timer)
    }
  }, [service, t])

  async function rename(event: FormEvent, device: ChatDevice) {
    event.preventDefault()
    if (!service || !draft.trim()) return
    setBusy(true)
    try {
      setDevices(await service.renameDevice(device.deviceId, draft.trim()))
      setEditing(null)
      toast.success(t('chat.devices.renamed'))
    } catch (error) {
      toast.error(chatErrorMessage(error, t))
    } finally {
      setBusy(false)
    }
  }

  async function revoke(device: ChatDevice, reset: boolean) {
    if (!service) return
    setBusy(true)
    try {
      if (reset) {
        setDevices(await service.resetIdentity([device.deviceId]))
        toast.success(t('chat.devices.revokedAndReset'))
      } else {
        setDevices(await service.revokeDevice(device.deviceId))
        toast.success(t('chat.devices.revoked'))
      }
    } catch (error) {
      toast.error(chatErrorMessage(error, t))
    } finally {
      setBusy(false)
    }
  }

  return (
    <SettingsSection title={t('chat.devices.title')} description={t('chat.devices.description')}>
      <p className="text-sm text-muted-foreground" data-testid="chat-device-status" data-device-id={service?.deviceId}>
        {t('chat.devices.thisOne', { device: service?.deviceId ?? '…' })}
      </p>
      <div>
        <Button variant="outline" onClick={() => setLinking(true)} disabled={!service} data-testid="chat-link-new-device">
          <Link2 />
          {t('chat.linkNew.action')}
        </Button>
      </div>
      <LinkNewDeviceDialog open={linking} onOpenChange={setLinking} />
      {devices === null ? (
        <p className="flex items-center gap-2 py-6 text-sm text-muted-foreground">
          <Loader2 className="size-4 animate-spin" aria-hidden />
          {t('chat.devices.loading')}
        </p>
      ) : (
        <ul className="max-w-2xl space-y-2" data-testid="chat-devices-list">
          {devices.map((device) => {
            const current = device.deviceId === service?.deviceId
            const seen = when(device.lastSeenAt, i18n.language)
            return (
              <li key={device.deviceId} className="flex items-center gap-3 rounded-lg border border-border p-3" data-testid={`chat-device-${device.deviceId}`}>
                <MonitorSmartphone className="size-5 shrink-0 text-muted-foreground" aria-hidden />
                <div className="min-w-0 flex-1">
                  {editing === device.deviceId ? (
                    <form className="flex items-center gap-2" onSubmit={(e) => void rename(e, device)}>
                      <Input
                        autoFocus
                        required
                        maxLength={64}
                        value={draft}
                        onChange={(e) => setDraft(e.target.value)}
                        aria-label={t('chat.devices.name')}
                        className="h-8"
                        data-testid={`chat-device-name-input-${device.deviceId}`}
                      />
                      <Button type="submit" variant="ghost" size="icon" className="size-8" disabled={busy || !draft.trim()} aria-label={t('common.save')} data-testid={`chat-device-name-save-${device.deviceId}`}>
                        {busy ? <Loader2 className="animate-spin" /> : <Check />}
                      </Button>
                      <Button type="button" variant="ghost" size="icon" className="size-8" disabled={busy} onClick={() => setEditing(null)} aria-label={t('common.cancel')}>
                        <X />
                      </Button>
                    </form>
                  ) : (
                    <p className="flex flex-wrap items-center gap-2">
                      <span className="truncate text-sm font-medium">{device.name || t('chat.device', { device: device.deviceId })}</span>
                      {current ? (
                        <span className="rounded-full bg-accent px-2 py-0.5 text-[0.6875rem] font-medium text-accent-foreground">{t('chat.devices.current')}</span>
                      ) : null}
                    </p>
                  )}
                  <p className="mt-1 text-xs text-muted-foreground">
                    {t('chat.devices.id', { device: device.deviceId })} ·{' '}
                    {t('chat.devices.created', { time: when(device.createdAt, i18n.language) ?? '—' })} ·{' '}
                    {seen ? t('chat.devices.lastSeen', { time: seen }) : t('chat.devices.neverSeen')}
                  </p>
                </div>
                {editing !== device.deviceId ? (
                  <Button
                    variant="ghost"
                    size="icon"
                    className="size-8"
                    disabled={busy}
                    onClick={() => {
                      setDraft(device.name)
                      setEditing(device.deviceId)
                    }}
                    aria-label={t('chat.devices.rename')}
                    data-testid={`chat-device-rename-${device.deviceId}`}
                  >
                    <Pencil />
                  </Button>
                ) : null}
                {!current && editing !== device.deviceId ? (
                  <Button size="sm" variant="outline" disabled={busy} onClick={() => { setResetIdentity(true); setRevoking(device) }} data-testid={`chat-device-revoke-${device.deviceId}`}>
                    {t('chat.devices.revoke')}
                  </Button>
                ) : null}
              </li>
            )
          })}
        </ul>
      )}
      <p className="max-w-2xl text-xs text-muted-foreground">{t('chat.devices.historyWarning')}</p>
      <ConfirmDestructive
        open={revoking !== null}
        onOpenChange={(open) => !open && setRevoking(null)}
        title={t('chat.devices.revokeTitle')}
        description={
          <>
            {t('chat.devices.confirm', { device: revoking ? revoking.name || t('chat.device', { device: revoking.deviceId }) : '' })}
            <span className="mt-3 flex items-start gap-2 text-foreground">
              <Checkbox
                id="chat-device-reset-identity"
                checked={resetIdentity}
                onCheckedChange={(value) => setResetIdentity(value === true)}
                data-testid="chat-device-reset-identity"
              />
              <label htmlFor="chat-device-reset-identity" className="grid gap-1 text-sm">
                <span className="font-medium">{t('chat.devices.resetIdentity')}</span>
                <span className="text-muted-foreground">{t('chat.devices.resetIdentityHint')}</span>
              </label>
            </span>
          </>
        }
        submit={resetIdentity ? t('chat.devices.revokeAndReset') : t('chat.devices.revoke')}
        errorFallback={t('chat.errors.unavailable')}
        onConfirm={() => {
          const device = revoking
          setRevoking(null)
          if (device) void revoke(device, resetIdentity)
        }}
      />
    </SettingsSection>
  )
}
