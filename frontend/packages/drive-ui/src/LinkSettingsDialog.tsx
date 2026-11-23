import { useEffect, useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Checkbox } from '@kutup/ui/components/checkbox'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { Input } from '@kutup/ui/components/input'
import { Label } from '@kutup/ui/components/label'
import { PasswordInput } from '@kutup/ui/components/password-input'
import { useDriveIdentity } from '@kutup/drive-core/identity'
import {
  LinkChanged,
  linkPassword,
  useLinkLimits,
  useSaveLinkSettings,
  type LinkSettingsLink,
  type LinkTarget,
} from '@kutup/drive-core/linkSettings'

/** A date input's value (`YYYY-MM-DD`) for `date`, in local time. */
function dateValue(date: Date): string {
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`
}

/** The end of the local day a date input's value names (Proton's choice: a link expires at day's end). */
function endOfDay(value: string): Date | null {
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(value)
  if (!match) return null
  return new Date(Number(match[1]), Number(match[2]) - 1, Number(match[3]), 23, 59, 59, 999)
}

/**
 * A public link's settings, as Proton Drive's (`PublicLinkSettingsModal`):
 * an expiry date and a password. The password is checked by no one but the
 * link's viewers' browsers and the server's count of wrong ones
 * (docs/plans/drive-link-password.md). Used by folder, album and file links.
 */
export function LinkSettingsDialog({
  link,
  target,
  onClose,
}: {
  link: LinkSettingsLink | null
  target: LinkTarget | null
  onClose: () => void
}) {
  const { t } = useTranslation()
  const identity = useDriveIdentity()
  const limits = useLinkLimits()
  const save = useSaveLinkSettings()
  const initialExpiry = link?.expiresAt ? dateValue(new Date(link.expiresAt)) : ''
  const [expiryOn, setExpiryOn] = useState(false)
  const [expiry, setExpiry] = useState('')
  const [passwordOn, setPasswordOn] = useState(false)
  const [password, setPassword] = useState('')
  // The current password, opened from the owner's copy; null while it opens.
  const [current, setCurrent] = useState<string | null>(null)
  const [discarding, setDiscarding] = useState(false)

  const linkId = link?.id
  useEffect(() => {
    if (!link || !identity.data) return
    setExpiryOn(Boolean(link.expiresAt))
    setExpiry(link.expiresAt ? dateValue(new Date(link.expiresAt)) : '')
    setCurrent(null)
    setDiscarding(false)
    save.reset()
    let live = true
    linkPassword(link, identity.data).then(
      (value) => {
        if (!live) return
        setCurrent(value)
        setPassword(value)
        setPasswordOn(value !== '')
      },
      () => live && setCurrent(''),
    )
    return () => {
      live = false
    }
    // Opened afresh for each link.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [linkId, identity.data])

  if (!link || !target) return null

  const maxChars = limits.data?.passwordMaxChars ?? 50
  const maxDays = limits.data?.maxExpiryDays ?? 3660
  const today = new Date()
  const min = dateValue(new Date(today.getFullYear(), today.getMonth(), today.getDate() + 1))
  // A day less than the maximum: the end of that day stays inside it.
  const max = dateValue(new Date(today.getFullYear(), today.getMonth(), today.getDate() + maxDays - 1))

  const newPassword = passwordOn ? password : ''
  const newExpiry = expiryOn && expiry ? expiry : ''
  const passwordChanged = current !== null && newPassword !== current
  const expiryChanged = newExpiry !== initialExpiry
  const dirty = passwordChanged || expiryChanged
  const tooLong = [...password].length > maxChars
  const expiryInvalid = expiryOn && expiry !== '' && (expiry < min || expiry > max)

  function close() {
    if (dirty && !save.isPending && !discarding) {
      setDiscarding(true)
      return
    }
    onClose()
  }

  function submit(e: FormEvent) {
    e.preventDefault()
    if (!link || !target || !dirty || tooLong || expiryInvalid) return
    save.mutate(
      {
        link,
        target,
        password: passwordChanged ? newPassword : undefined,
        expiresAt: expiryChanged ? (newExpiry ? endOfDay(newExpiry) : null) : undefined,
      },
      {
        onSuccess: () => {
          toast.success(t('linkSettings.saved'))
          onClose()
        },
      },
    )
  }

  const error = save.error
    ? save.error instanceof LinkChanged
      ? t('linkSettings.changed')
      : t('linkSettings.failed')
    : null

  return (
    <Dialog open onOpenChange={(open) => !open && close()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{t('linkSettings.title')}</DialogTitle>
          <DialogDescription>{t('linkSettings.description')}</DialogDescription>
        </DialogHeader>
        <form className="space-y-5" onSubmit={submit} data-testid="link-settings">
          <section className="space-y-2">
            <div className="flex items-start gap-3">
              <Checkbox
                id="link-expiry-on"
                checked={expiryOn}
                disabled={save.isPending}
                onCheckedChange={(value) => setExpiryOn(value === true)}
                data-testid="link-expiry-toggle"
              />
              <div className="space-y-0.5">
                <Label htmlFor="link-expiry-on">{t('linkSettings.expiry')}</Label>
                <p className="text-xs text-muted-foreground">{t('linkSettings.expiryHint')}</p>
              </div>
            </div>
            {expiryOn ? (
              <Input
                type="date"
                aria-label={t('linkSettings.expiryDate')}
                className="w-48"
                min={min}
                max={max}
                value={expiry}
                disabled={save.isPending}
                aria-invalid={expiryInvalid}
                onChange={(e) => setExpiry(e.target.value)}
                data-testid="link-expiry-date"
              />
            ) : null}
            {expiryInvalid ? <p className="text-xs text-destructive">{t('linkSettings.expiryRange', { count: maxDays })}</p> : null}
          </section>

          <section className="space-y-2">
            <div className="flex items-start gap-3">
              <Checkbox
                id="link-password-on"
                checked={passwordOn}
                disabled={save.isPending || current === null}
                onCheckedChange={(value) => setPasswordOn(value === true)}
                data-testid="link-password-toggle"
              />
              <div className="space-y-0.5">
                <Label htmlFor="link-password-on">{t('linkSettings.password')}</Label>
                <p className="text-xs text-muted-foreground">{t('linkSettings.passwordHint')}</p>
              </div>
            </div>
            {passwordOn ? (
              <PasswordInput
                aria-label={t('linkSettings.passwordField')}
                placeholder={t('linkSettings.passwordPlaceholder')}
                autoComplete="new-password"
                data-protonpass-autosave-ignore="true"
                className="w-64"
                value={password}
                disabled={save.isPending}
                aria-invalid={tooLong}
                onChange={(e) => setPassword(e.target.value)}
                data-testid="link-password-input"
              />
            ) : null}
            {tooLong ? <p className="text-xs text-destructive">{t('linkSettings.passwordTooLong', { count: maxChars })}</p> : null}
          </section>

          {discarding ? (
            <Alert variant="warn">
              <p className="font-medium">{t('linkSettings.discardTitle')}</p>
              <p className="mt-1 text-sm">{t('linkSettings.discardBody')}</p>
              <div className="mt-3 flex justify-end gap-2">
                <Button type="button" size="sm" variant="outline" onClick={() => setDiscarding(false)}>
                  {t('linkSettings.keepEditing')}
                </Button>
                <Button type="button" size="sm" variant="destructive" onClick={onClose}>
                  {t('linkSettings.discard')}
                </Button>
              </div>
            </Alert>
          ) : null}
          {error ? <Alert variant="error">{error}</Alert> : null}

          <DialogFooter>
            <Button type="button" variant="outline" onClick={close} disabled={save.isPending}>
              {t('common.cancel')}
            </Button>
            <Button type="submit" loading={save.isPending} disabled={!dirty || tooLong || expiryInvalid} data-testid="link-settings-save">
              {t('linkSettings.save')}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
