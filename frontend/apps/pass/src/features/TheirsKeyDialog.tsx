import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { Field } from '@kutup/ui/components/field'
import { PasswordInput } from '@kutup/ui/components/password-input'
import type { VaultSession } from '../sync/vaultSession'
import { VaultError } from '../vault/client'
import { KeyFileInput } from './KeyFileInput'

/**
 * Another device saved the vault under a new password or key file: it is
 * needed to merge this device's edits with theirs (the new key is kept).
 */
export function TheirsKeyDialog({ session, open }: { session: VaultSession; open: boolean }) {
  const { t } = useTranslation()
  const [password, setPassword] = useState('')
  const [keyFile, setKeyFile] = useState<{ name: string; contents: Uint8Array } | null>(null)
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const submit = async () => {
    setPending(true)
    setError(null)
    try {
      await session.provideTheirsKey({ password: password || null, keyFile: keyFile?.contents ?? null })
    } catch (failure) {
      setError(failure instanceof VaultError ? t('unlock.wrongKey') : t('sync.error'))
    } finally {
      setPending(false)
    }
  }
  return (
    <Dialog open={open}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{t('theirsKey.title')}</DialogTitle>
          <DialogDescription>{t('theirsKey.description')}</DialogDescription>
        </DialogHeader>
        <form
          className="mt-4 space-y-4"
          onSubmit={(e) => {
            e.preventDefault()
            void submit()
          }}
        >
          <Field label={t('theirsKey.password')}>
            {(field) => <PasswordInput {...field} value={password} onChange={(e) => setPassword(e.target.value)} autoFocus />}
          </Field>
          <div className="space-y-1.5">
            <span className="text-sm font-medium">{t('keyFile.label')}</span>
            <KeyFileInput value={keyFile} onChange={setKeyFile} />
          </div>
          {error ? <Alert variant="error">{error}</Alert> : null}
          <DialogFooter>
            <Button type="submit" loading={pending} disabled={!password && !keyFile}>
              {t('theirsKey.submit')}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
