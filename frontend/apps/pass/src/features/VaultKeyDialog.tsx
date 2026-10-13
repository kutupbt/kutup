import { Copy, Eye, EyeOff } from 'lucide-react'
import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { ReauthLockedError, verifyAccountPassword } from '@kutup/session/reauth'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { Field } from '@kutup/ui/components/field'
import { PasswordInput } from '@kutup/ui/components/password-input'
import { copySecret } from '../lib/copySecret'

/** A generated vault key, hidden until asked, with a copy button. */
export function VaultKeyShown({ value, warning }: { value: string; warning?: string }) {
  const { t } = useTranslation()
  const [shown, setShown] = useState(false)
  return (
    <div className="space-y-2">
      {warning ? <Alert variant="warn">{warning}</Alert> : null}
      <div className="flex items-center gap-2 rounded-md border border-border bg-muted/50 px-3 py-2">
        <code className="flex-1 font-mono text-sm tracking-wide" aria-label={t('vaultKey.label')}>
          {shown ? value : '•••••-•••••-•••••-•••••-•••••'}
        </code>
        <Button type="button" variant="ghost" size="icon" onClick={() => setShown(!shown)} aria-label={shown ? t('common.hidePassword') : t('common.showPassword')}>
          {shown ? <EyeOff /> : <Eye />}
        </Button>
        <Button
          type="button"
          variant="ghost"
          size="icon"
          onClick={() => void copySecret(value, t('vaultKey.copied'), t('detail.clipboardCleared'), t('detail.clipboardNotCleared'))}
          aria-label={t('vaultKey.copy')}
        >
          <Copy />
        </Button>
      </div>
    </div>
  )
}

/**
 * Shows the key Kutup Pass generated for a vault, for a KeePass app on
 * another device (docs/plans/pass.md, "Vault keys"), after the account
 * password is given again.
 */
export function VaultKeyDialog({
  open,
  onOpenChange,
  vaultName,
  reveal,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  vaultName: string
  /** The generated key, from the account. */
  reveal: () => Promise<string | null>
}) {
  const { t } = useTranslation()
  const [password, setPassword] = useState('')
  const [key, setKey] = useState<string | null>(null)
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    setPassword('')
    setKey(null)
    setError(null)
  }, [open])

  const submit = async () => {
    setPending(true)
    setError(null)
    try {
      if (!(await verifyAccountPassword(password))) {
        setError(t('unlock.wrongAccountPassword'))
        return
      }
      const value = await reveal()
      if (value) setKey(value)
      else setError(t('vaultKey.none'))
    } catch (failure) {
      setError(failure instanceof ReauthLockedError ? t('unlock.paused') : t('unlock.checkUnreachable'))
    } finally {
      setPassword('')
      setPending(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={(next) => !pending && onOpenChange(next)}>
      <DialogContent className="sm:max-w-md">
        <form
          onSubmit={(e) => {
            e.preventDefault()
            if (!key) void submit()
          }}
        >
          <DialogHeader>
            <DialogTitle>{t('vaultKey.title', { name: vaultName })}</DialogTitle>
            <DialogDescription>{t('vaultKey.description')}</DialogDescription>
          </DialogHeader>
          <div className="mt-4 space-y-4">
            {key ? (
              <VaultKeyShown value={key} />
            ) : (
              <Field label={t('unlock.accountPassword')}>
                {(field) => <PasswordInput {...field} value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" autoFocus />}
              </Field>
            )}
            {error ? <Alert variant="error">{error}</Alert> : null}
          </div>
          <DialogFooter className="mt-6">
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)} disabled={pending}>
              {t('common.close')}
            </Button>
            {key ? null : (
              <Button type="submit" loading={pending} disabled={!password}>
                {t('vaultKey.reveal')}
              </Button>
            )}
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
