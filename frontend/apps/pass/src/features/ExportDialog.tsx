import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { ReauthLockedError, verifyAccountPassword } from '@kutup/session/reauth'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { Field } from '@kutup/ui/components/field'
import { PasswordInput } from '@kutup/ui/components/password-input'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@kutup/ui/components/select'
import type { VaultSession } from '../sync/vaultSession'

type ExportFormat = 'csv' | 'xml'

/** Saves `contents` as a download named `name`; it goes nowhere else. */
function downloadFile(contents: string | Uint8Array, type: string, name: string) {
  const url = URL.createObjectURL(new Blob([contents as BlobPart], { type }))
  try {
    const link = document.createElement('a')
    link.href = url
    link.download = name
    document.body.append(link)
    link.click()
    link.remove()
  } finally {
    setTimeout(() => URL.revokeObjectURL(url), 30_000)
  }
}

/**
 * Exports the vault as a CSV in the clear (docs/plans/pass-gaps-2.md P5), in
 * KeePassXC's columns. The account's password is asked first, as Proton
 * Pass asks before an export (many vaults open with a key the account keeps,
 * so their owners may not know the vault's own password); the file is made
 * in the worker and only downloaded.
 */
export function ExportDialog({ session, title, open, onOpenChange }: { session: VaultSession; title: string; open: boolean; onOpenChange: (open: boolean) => void }) {
  const { t } = useTranslation()
  const [format, setFormat] = useState<ExportFormat>('csv')
  const [password, setPassword] = useState('')
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<string | null>(null)
  useEffect(() => {
    setPassword('')
    setError(null)
  }, [open])

  const submit = async () => {
    setPending(true)
    setError(null)
    try {
      if (!(await verifyAccountPassword(password))) {
        setError(t('export.wrongPassword'))
        return
      }
      const name = (title || 'vault').replace(/[\\/:*?"<>|]/g, '_')
      if (format === 'xml') downloadFile(await session.vault().exportKeePassXml(), 'application/xml', `${name}.xml`)
      else downloadFile(await session.vault().exportCsv(), 'text/csv;charset=utf-8', `${name}.csv`)
      toast.success(t('export.done'))
      onOpenChange(false)
    } catch (failure) {
      setError(
        failure instanceof ReauthLockedError
          ? t(failure.reason === 'rateLimited' ? 'export.slowDown' : 'export.locked')
          : t('export.failed'),
      )
    } finally {
      setPassword('')
      setPending(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={(next) => !pending && onOpenChange(next)}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{t('export.title')}</DialogTitle>
          <DialogDescription>{t('export.description')}</DialogDescription>
        </DialogHeader>
        <form
          className="mt-4 space-y-4"
          onSubmit={(event) => {
            event.preventDefault()
            if (password) void submit()
          }}
        >
          <Field label={t('export.format')} description={t(`export.formats.${format}Hint`)}>
            {(field) => (
              <Select value={format} onValueChange={(value) => setFormat(value as ExportFormat)}>
                <SelectTrigger id={field.id}>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {(['csv', 'xml'] as const).map((value) => (
                    <SelectItem key={value} value={value}>
                      {t(`export.formats.${value}`)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            )}
          </Field>
          <Alert variant="warn" title={t('export.warningTitle')}>
            {t('export.warning')}
          </Alert>
          <Field label={t('export.password')} description={t('export.passwordHint')} required>
            {(field) => <PasswordInput {...field} value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" autoFocus required />}
          </Field>
          {error ? <Alert variant="error">{error}</Alert> : null}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)} disabled={pending}>
              {t('common.cancel')}
            </Button>
            <Button type="submit" loading={pending} disabled={!password}>
              {t(format === 'xml' ? 'export.submitXml' : 'export.submit')}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
