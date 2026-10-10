import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { MIN_MAIL_KEY_PASSPHRASE, WrongKeyPassphrase } from '@kutup/crypto'
import { useRequiredSession } from '@kutup/session/store'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Checkbox } from '@kutup/ui/components/checkbox'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { Field } from '@kutup/ui/components/field'
import { Input } from '@kutup/ui/components/input'
import { PasswordInput } from '@kutup/ui/components/password-input'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { exportKey, KeyAlreadyThere, useImportKey, useNewKey, type CheckedMailAddress, type MailKey } from './mailKeys'

/** Largest key file read. */
const MAX_KEY_FILE = 64 * 1024

function save(name: string, text: string) {
  const url = URL.createObjectURL(new Blob([text], { type: 'application/pgp-keys' }))
  const link = document.createElement('a')
  link.href = url
  link.download = name
  link.click()
  setTimeout(() => URL.revokeObjectURL(url), 30_000)
}

/** A new key for new mail; the others stay to open older mail. */
export function NewKeyDialog({ address, onClose }: { address: CheckedMailAddress; onClose: () => void }) {
  const { t } = useTranslation()
  const create = useNewKey()
  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{t('settings.keys.newTitle')}</DialogTitle>
          <DialogDescription>{t('settings.keys.newDescription')}</DialogDescription>
        </DialogHeader>
        {create.isError ? <Alert variant="error">{apiErrorMessage(create.error, t('settings.keys.changeFailed'))}</Alert> : null}
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            {t('common.cancel')}
          </Button>
          <Button
            loading={create.isPending}
            onClick={() =>
              create.mutate(address, {
                onSuccess: () => {
                  toast.success(t('settings.keys.newDone'))
                  onClose()
                },
              })
            }
          >
            {t('settings.keys.newSubmit')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

/** Imports a key from an OpenPGP secret key file (Kutup's export, Proton's or GnuPG's). */
export function ImportKeyDialog({ address, onClose }: { address: CheckedMailAddress; onClose: () => void }) {
  const { t } = useTranslation()
  const importKey = useImportKey()
  const [file, setFile] = useState<File | null>(null)
  const [passphrase, setPassphrase] = useState('')
  const [primary, setPrimary] = useState(true)
  const [problem, setProblem] = useState<string | null>(null)

  async function submit() {
    if (!file) return
    setProblem(null)
    if (file.size > MAX_KEY_FILE) {
      setProblem(t('settings.keys.importNotAKey'))
      return
    }
    importKey.mutate(
      { address, file: new Uint8Array(await file.arrayBuffer()), passphrase, primary },
      {
        onSuccess: () => {
          toast.success(t('settings.keys.importDone'))
          onClose()
        },
        onError: (error) =>
          setProblem(
            error instanceof WrongKeyPassphrase
              ? t('settings.keys.importWrongPassphrase')
              : error instanceof KeyAlreadyThere
                ? t('settings.keys.importAlreadyThere')
                : (error as { response?: unknown }).response
                  ? apiErrorMessage(error, t('settings.keys.changeFailed'))
                  : t('settings.keys.importNotUsable', { address: address.address }),
          ),
      },
    )
  }

  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{t('settings.keys.importTitle')}</DialogTitle>
          <DialogDescription>{t('settings.keys.importDescription', { address: address.address })}</DialogDescription>
        </DialogHeader>
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault()
            void submit()
          }}
        >
          <Field label={t('settings.keys.importFile')}>
            {(field) => (
              <Input
                {...field}
                type="file"
                accept=".asc,.gpg,.pgp,.key,application/pgp-keys"
                onChange={(e) => setFile(e.target.files?.[0] ?? null)}
              />
            )}
          </Field>
          <Field label={t('settings.keys.passphrase')} description={t('settings.keys.importPassphraseHint')}>
            {(field) => <PasswordInput {...field} autoComplete="off" value={passphrase} onChange={(e) => setPassphrase(e.target.value)} />}
          </Field>
          <label className="flex items-start gap-2 text-sm">
            <Checkbox checked={primary} onCheckedChange={(on) => setPrimary(on === true)} className="mt-0.5" />
            <span>{t('settings.keys.importPrimary')}</span>
          </label>
          {problem ? <Alert variant="error">{problem}</Alert> : null}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose}>
              {t('common.cancel')}
            </Button>
            <Button type="submit" disabled={!file} loading={importKey.isPending}>
              {t('settings.keys.importSubmit')}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

/** Saves a key's private part as a file locked with a passphrase the person chooses. */
export function ExportKeyDialog({ address, mailKey, onClose }: { address: string; mailKey: MailKey; onClose: () => void }) {
  const { t } = useTranslation()
  const session = useRequiredSession()
  const [passphrase, setPassphrase] = useState('')
  const [again, setAgain] = useState('')
  const [busy, setBusy] = useState(false)
  const short = passphrase.length > 0 && [...passphrase].length < MIN_MAIL_KEY_PASSPHRASE
  const mismatch = again.length > 0 && again !== passphrase

  async function submit() {
    if ([...passphrase].length < MIN_MAIL_KEY_PASSPHRASE || again !== passphrase) return
    setBusy(true)
    try {
      const armored = await exportKey(session, address, mailKey, passphrase)
      // Proton's name for the same file.
      save(`privatekey.${address}-${mailKey.fingerprint}.asc`, armored)
      toast.success(t('settings.keys.exportDone'))
      onClose()
    } catch (error) {
      toast.error(apiErrorMessage(error, t('settings.keys.exportFailed')))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{t('settings.keys.exportTitle')}</DialogTitle>
          <DialogDescription>{t('settings.keys.exportDescription')}</DialogDescription>
        </DialogHeader>
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault()
            void submit()
          }}
        >
          <Field label={t('settings.keys.passphrase')} error={short ? t('settings.keys.passphraseShort', { count: MIN_MAIL_KEY_PASSPHRASE }) : undefined}>
            {(field) => <PasswordInput {...field} autoComplete="new-password" value={passphrase} onChange={(e) => setPassphrase(e.target.value)} />}
          </Field>
          <Field label={t('settings.keys.passphraseAgain')} error={mismatch ? t('settings.keys.passphraseMismatch') : undefined}>
            {(field) => <PasswordInput {...field} autoComplete="new-password" value={again} onChange={(e) => setAgain(e.target.value)} />}
          </Field>
          <Alert variant="warn">{t('settings.keys.exportWarning')}</Alert>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose}>
              {t('common.cancel')}
            </Button>
            <Button type="submit" disabled={[...passphrase].length < MIN_MAIL_KEY_PASSPHRASE || again !== passphrase} loading={busy}>
              {t('settings.keys.exportSubmit')}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
