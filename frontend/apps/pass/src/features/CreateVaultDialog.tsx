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
import { randomVaultKey, strengthOf } from '../lib/generator'
import { freshKeys } from '../sync/openVaults'
import { VaultHandle } from '../vault/client'
import { KeyFileInput } from './KeyFileInput'
import { VaultKeyShown } from './VaultKeyDialog'

/**
 * Makes a new vault: a KeePass file in a Drive folder, with its own key. As
 * in Proton Pass, the key is by default a random one kept in the account
 * (docs/plans/pass.md, "Vault keys"), shown on asking for a KeePass app; or
 * a password and/or key file the person chooses.
 */
export function CreateVaultDialog({
  open,
  onOpenChange,
  folderId: wantedFolder = null,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  /** The folder to make it in (Drive's New menu); else My files. */
  folderId?: string | null
}) {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const session = useRequiredSession()
  const { folders, root } = useVaultFiles()
  const createFile = useCreateVaultFile()
  const keepKey = useKeepVaultKey()
  const [name, setName] = useState('')
  const [folderId, setFolderId] = useState('')
  const [mode, setMode] = useState<'random' | 'chosen'>('random')
  /** A generated key that could not be kept, and its vault: shown until kept or saved. */
  const [unkept, setUnkept] = useState<{ key: string; fileId: string } | null>(null)
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
    setMode('random')
    setUnkept(null)
    setFolderId('')
    setPassword('')
    setConfirm('')
    setKeyFile(null)
    setRemember(true)
    setError(null)
  }, [open, t])

  const random = mode === 'random'
  const mismatch = !random && confirm.length > 0 && password !== confirm
  const noKey = !random && !password && !keyFile
  // Until one is chosen: the folder Drive asked for, else My files.
  const chosen = folderId || (wantedFolder && writable.some((f) => f.id === wantedFolder) ? wantedFolder : (root?.id ?? ''))
  const folder = writable.find((f) => f.id === chosen)

  const submit = async () => {
    if (!folder || !name.trim() || mismatch || noKey || unkept) return
    setPending(true)
    setError(null)
    const generated = random ? randomVaultKey() : null
    const key = generated ? { password: generated, keyFile: null } : { password: password || null, keyFile: keyFile?.contents ?? null }
    try {
      const vault = await VaultHandle.create(name.trim(), key)
      const contents = await vault.save()
      await vault.close()
      const fileId = await createFile(folder, name.trim(), contents)
      freshKeys.set(fileId, key)
      if (generated || remember) {
        try {
          await keepKey(session, fileId, key, Boolean(generated))
        } catch {
          if (generated) {
            // Kept nowhere else: shown now, or the vault is lost.
            setUnkept({ key: generated, fileId })
            toast.error(t('vaultKey.notKept'))
            return
          }
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

  const finish = (fileId: string) => {
    setUnkept(null)
    toast.success(t('vaults.created'))
    onOpenChange(false)
    void navigate(`/v/${fileId}`)
  }

  const keepAgain = async () => {
    if (!unkept) return
    setPending(true)
    try {
      await keepKey(session, unkept.fileId, { password: unkept.key, keyFile: null }, true)
      finish(unkept.fileId)
    } catch {
      toast.error(t('vaultKey.notKept'))
    } finally {
      setPending(false)
    }
  }

  return (
    // A key kept nowhere yet: no closing until it is kept or saved.
    <Dialog open={open} onOpenChange={(next) => !pending && !unkept && onOpenChange(next)}>
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
              <Select value={chosen} onValueChange={setFolderId}>
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
          <fieldset className="space-y-2">
            <legend className="text-sm font-medium">{t('vaultKey.choice')}</legend>
            {(['random', 'chosen'] as const).map((value) => (
              <label key={value} className="flex items-start gap-2 rounded-md border border-border p-2.5 text-sm has-[:checked]:border-primary">
                <input type="radio" name="vault-key" className="mt-1" checked={mode === value} onChange={() => setMode(value)} />
                <span>
                  <span className="block font-medium">{t(`vaultKey.${value}`)}</span>
                  <span className="block text-xs text-muted-foreground">{t(`vaultKey.${value}Description`)}</span>
                </span>
              </label>
            ))}
          </fieldset>
          {random ? null : (
          <>
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
          </>
          )}
          {noKey ? <p className="text-xs text-muted-foreground">{t('vaults.needsKey')}</p> : null}
          {error ? <Alert variant="error">{error}</Alert> : null}
          {unkept ? <VaultKeyShown value={unkept.key} warning={t('vaultKey.notKeptDescription')} /> : null}
          {unkept ? (
            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => finish(unkept.fileId)} disabled={pending}>
                {t('vaultKey.saved')}
              </Button>
              <Button type="button" loading={pending} onClick={() => void keepAgain()}>
                {t('vaultKey.keepAgain')}
              </Button>
            </DialogFooter>
          ) : (
            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => onOpenChange(false)} disabled={pending}>
                {t('common.cancel')}
              </Button>
              <Button type="submit" loading={pending} disabled={!folder || !name.trim() || mismatch || noKey}>
                {t('vaults.create')}
              </Button>
            </DialogFooter>
          )}
        </form>
      </DialogContent>
    </Dialog>
  )
}
