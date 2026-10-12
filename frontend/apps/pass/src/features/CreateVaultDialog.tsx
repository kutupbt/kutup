import { useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'
import { toast } from 'sonner'
import { useRequiredSession } from '@kutup/session/store'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Checkbox } from '@kutup/ui/components/checkbox'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { Field } from '@kutup/ui/components/field'
import { Input } from '@kutup/ui/components/input'
import { Label } from '@kutup/ui/components/label'
import { PasswordInput } from '@kutup/ui/components/password-input'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@kutup/ui/components/select'
import { useKeepVaultKey } from '../drive/secrets'
import { useCreateVaultFile, useVaultFiles } from '../drive/vaults'
import { strengthOf } from '../lib/generator'
import { freshKeys } from '../sync/openVaults'
import { VaultHandle } from '../vault/client'
import { KeyFileInput } from './KeyFileInput'

/** Makes a new vault: a KeePass file in a Drive folder, with its own key. */
export function CreateVaultDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const session = useRequiredSession()
  const { folders, root } = useVaultFiles()
  const createFile = useCreateVaultFile()
  const keepKey = useKeepVaultKey()
  const [name, setName] = useState('')
  const [folderId, setFolderId] = useState('')
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [keyFile, setKeyFile] = useState<{ name: string; contents: Uint8Array } | null>(null)
  const [remember, setRemember] = useState(true)
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const writable = useMemo(
    () =>
      folders
        .filter((f) => f.key && f.canUpload && (f.source === 'owned' || f.source === 'shared'))
        .sort((a, b) => Number(b.isRoot) - Number(a.isRoot) || (a.name ?? '').localeCompare(b.name ?? '')),
    [folders],
  )

  useEffect(() => {
    if (!open) return
    setName(t('vaults.defaultName'))
    setFolderId(root?.id ?? '')
    setPassword('')
    setConfirm('')
    setKeyFile(null)
    setRemember(true)
    setError(null)
  }, [open, root, t])

  const mismatch = confirm.length > 0 && password !== confirm
  const noKey = !password && !keyFile
  const folder = writable.find((f) => f.id === folderId)

  const submit = async () => {
    if (!folder || !name.trim() || mismatch || noKey) return
    setPending(true)
    setError(null)
    const key = { password: password || null, keyFile: keyFile?.contents ?? null }
    try {
      const vault = await VaultHandle.create(name.trim(), key)
      const contents = await vault.save()
      await vault.close()
      const fileId = await createFile(folder, name.trim(), contents)
      freshKeys.set(fileId, key)
      if (remember) {
        try {
          await keepKey(session, fileId, key)
        } catch {
          toast.error(t('unlock.keepFailed'))
        }
      }
      toast.success(t('vaults.created'))
      onOpenChange(false)
      void navigate(`/v/${fileId}`)
    } catch {
      setError(t('vaults.createFailed'))
    } finally {
      setPending(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={(next) => !pending && onOpenChange(next)}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{t('vaults.newTitle')}</DialogTitle>
          <DialogDescription>{t('vaults.newDescription')}</DialogDescription>
        </DialogHeader>
        <form
          className="mt-4 space-y-4"
          onSubmit={(e) => {
            e.preventDefault()
            void submit()
          }}
        >
          <Field label={t('vaults.name')} required>
            {(field) => <Input {...field} value={name} onChange={(e) => setName(e.target.value)} maxLength={200} required autoFocus />}
          </Field>
          <Field label={t('vaults.folder')} description={t('vaults.folderDescription')}>
            {(field) => (
              <Select value={folderId} onValueChange={setFolderId}>
                <SelectTrigger id={field.id} aria-describedby={field['aria-describedby']}>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {writable.map((f) => (
                    <SelectItem key={f.id} value={f.id}>
                      {f.isRoot ? t('vaults.myFiles') : (f.name ?? t('vaults.unnamedFolder'))}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            )}
          </Field>
          <Field
            label={t('vaults.password')}
            description={password ? t(`strength.${strengthOf(password)}`) : t('vaults.passwordDescription')}
          >
            {(field) => <PasswordInput {...field} value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" />}
          </Field>
          <Field label={t('vaults.confirmPassword')} error={mismatch ? t('vaults.mismatch') : undefined}>
            {(field) => <PasswordInput {...field} value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="new-password" />}
          </Field>
          <div className="space-y-1.5">
            <span className="text-sm font-medium">{t('keyFile.label')}</span>
            <KeyFileInput value={keyFile} onChange={setKeyFile} />
          </div>
          <div className="flex items-start gap-2">
            <Checkbox id="vault-remember" checked={remember} onCheckedChange={(v) => setRemember(v === true)} />
            <div className="space-y-0.5">
              <Label htmlFor="vault-remember">{t('unlock.remember')}</Label>
              <p className="text-xs text-muted-foreground">{t('unlock.rememberDescription')}</p>
            </div>
          </div>
          {noKey ? <p className="text-xs text-muted-foreground">{t('vaults.needsKey')}</p> : null}
          {error ? <Alert variant="error">{error}</Alert> : null}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)} disabled={pending}>
              {t('common.cancel')}
            </Button>
            <Button type="submit" loading={pending} disabled={!folder || !name.trim() || mismatch || noKey}>
              {t('vaults.create')}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
