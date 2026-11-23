import { FolderPlus } from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'
import { toast } from 'sonner'
import { useCreateFolder } from '@kutup/drive-core/mutations'
import { canonicalName } from '@kutup/drive-core/names'
import { NameDialog } from '@kutup/drive-ui/NameDialog'
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
import { putKeptKey, sealVaultKey, secretsKey, type SealedKey } from '../drive/secrets'
import { useCreateVaultFile, useVaultFiles } from '../drive/vaults'
import { canMakeSubfolder, vaultFolderChoices } from '../lib/folderPaths'
import { randomVaultKey, strengthOf } from '../lib/generator'
import { keyFileName, NEW_VAULT_KEY_FILE_CHOICES, newVaultKeyProblem, type NewVaultKeyForm } from '../lib/keyChange'
import { freshKeys } from '../sync/openVaults'
import { VaultHandle } from '../vault/client'
import { GeneratedKeyFileField } from './GeneratedKeyFile'
import { KeyFileInput } from './KeyFileInput'
import { useGeneratedKeyFile } from './useGeneratedKeyFile'
import { VaultKeyShown } from './VaultKeyDialog'

/**
 * Makes a new vault: a KeePass file in a Drive folder, with its own key. As
 * in Proton Pass, the key is by default a random one kept in the account
 * (docs/plans/pass.md, "Vault keys"), shown on asking for a KeePass app; or
 * a password and/or key file the person chooses: one they have, or one
 * generated here (KeePassXC's New Database wizard), downloaded and said
 * saved before the vault is made, and wiped when the dialog goes. The
 * folder is any Drive folder it may be saved in, or a new one made here.
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
  const queryClient = useQueryClient()
  const [name, setName] = useState('')
  const [folderId, setFolderId] = useState('')
  // A folder just made here, chosen once Drive's folder list has it.
  const [madeFolder, setMadeFolder] = useState<string | null>(null)
  const [mode, setMode] = useState<'random' | 'chosen'>('random')
  /** A generated key that could not be kept, and its vault: shown until kept or saved. */
  const [unkept, setUnkept] = useState<{ key: string; fileId: string; sealed: SealedKey | null } | null>(null)
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [keyFileMode, setKeyFileMode] = useState<NewVaultKeyForm['keyFile']>('none')
  const [keyFile, setKeyFile] = useState<{ name: string; contents: Uint8Array } | null>(null)
  const generated = useGeneratedKeyFile()
  const createFolder = useCreateFolder()
  const [naming, setNaming] = useState(false)
  const [remember, setRemember] = useState(true)
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const writable = useMemo(
    () => vaultFolderChoices(folders, { myFiles: t('vaults.myFiles'), unnamed: t('vaults.unnamedFolder') }),
    [folders, t],
  )
  const { forget: forgetGenerated } = generated
  const { reset: resetCreateFolder } = createFolder

  useEffect(() => {
    // A generated key file lives only in this dialog: wiped when it goes.
    forgetGenerated()
    if (!open) return
    setName(t('vaults.defaultName'))
    setMode('random')
    setUnkept(null)
    setFolderId('')
    setMadeFolder(null)
    setPassword('')
    setConfirm('')
    setKeyFileMode('none')
    setKeyFile(null)
    setNaming(false)
    resetCreateFolder()
    setRemember(true)
    setError(null)
  }, [open, t, forgetGenerated, resetCreateFolder])

  const random = mode === 'random'
  const mismatch = !random && confirm.length > 0 && password !== confirm
  const problem = random
    ? null
    : newVaultKeyProblem({
        password,
        confirm,
        keyFile: keyFileMode,
        generated: generated.name !== null,
        generatedSaved: generated.saved,
        chosen: keyFile !== null,
      })
  useEffect(() => {
    if (madeFolder && writable.some((c) => c.folder.id === madeFolder)) {
      setFolderId(madeFolder)
      setMadeFolder(null)
    }
  }, [madeFolder, writable])

  // Until one is chosen: the folder Drive asked for, else My files.
  const chosen = folderId || (wantedFolder && writable.some((c) => c.folder.id === wantedFolder) ? wantedFolder : (root?.id ?? ''))
  const choice = writable.find((c) => c.folder.id === chosen)
  const folder = choice?.folder
  // Names a new subfolder may not take: its siblings' (the server checks files too).
  const taken = useMemo(
    () => new Set(folders.flatMap((f) => (folder && f.parentId === folder.id && f.name ? [canonicalName(f.name)] : []))),
    [folders, folder],
  )

  const makeKeyFile = async () => {
    setError(null)
    if (!(await generated.make(keyFileName(name.trim() || t('vaults.defaultName'))))) setError(t('changeKey.generateFailed'))
  }

  const submit = async () => {
    if (!folder || !name.trim() || problem || unkept) return
    setPending(true)
    setError(null)
    const madeKey = random ? randomVaultKey() : null
    // A copy: the dialog's generated key file is wiped when it closes.
    const chosenFile = keyFileMode === 'generate' ? (generated.bytes()?.slice() ?? null) : keyFileMode === 'choose' ? (keyFile?.contents ?? null) : null
    const key = madeKey ? { password: madeKey, keyFile: null } : { password: password || null, keyFile: chosenFile }
    try {
      const vault = await VaultHandle.create(name.trim(), key)
      let fileId: string
      let sealed: SealedKey | null = null
      let kept = !(madeKey || remember)
      try {
        const contents = await vault.save()
        fileId = await createFile(folder, name.trim(), contents)
        // The vault is in Drive from here on: nothing below may lose its key.
        if (!kept) {
          try {
            // Sealed in the worker from the key this vault was made with.
            sealed = await sealVaultKey(session, fileId, vault, 0, Boolean(madeKey))
            await putKeptKey(session, fileId, sealed)
            await queryClient.invalidateQueries({ queryKey: secretsKey })
            kept = true
          } catch {
            // Shown below, or kept again from `sealed`.
          }
        }
      } finally {
        await vault.close().catch(() => undefined)
      }
      freshKeys.set(fileId, key)
      if (!kept) {
        if (madeKey) {
          // Kept nowhere else: shown now, or the vault is lost.
          setUnkept({ key: madeKey, fileId, sealed })
          toast.error(t('vaultKey.notKept'))
          return
        }
        toast.error(t('unlock.keepFailed'))
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
    if (!unkept?.sealed) return
    setPending(true)
    try {
      await putKeptKey(session, unkept.fileId, unkept.sealed)
      await queryClient.invalidateQueries({ queryKey: secretsKey })
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
              <div className="flex items-center gap-2">
                <Select value={chosen} onValueChange={(id) => id && setFolderId(id)}>
                  <SelectTrigger id={field.id} aria-describedby={field['aria-describedby']} className="min-w-0 flex-1">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {writable.map((c) => (
                      <SelectItem key={c.folder.id} value={c.folder.id}>
                        {c.path}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                {canMakeSubfolder(folder) ? (
                  <Button type="button" variant="outline" size="sm" className="shrink-0" onClick={() => setNaming(true)} disabled={pending || madeFolder !== null}>
                    <FolderPlus />
                    {t('vaults.newFolder')}
                  </Button>
                ) : null}
              </div>
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
          <fieldset className="space-y-2">
            <legend className="text-sm font-medium">{t('keyFile.label')}</legend>
            <p className="text-xs text-muted-foreground">{t('vaults.keyFileDescription')}</p>
            {NEW_VAULT_KEY_FILE_CHOICES.map((value) => (
              <label key={value} className="flex items-center gap-2 text-sm">
                <input type="radio" name="new-vault-key-file" checked={keyFileMode === value} onChange={() => setKeyFileMode(value)} />
                {t(`changeKey.keyFileChoice.${value}`)}
              </label>
            ))}
            {keyFileMode === 'generate' ? (
              <div className="pl-6">
                <GeneratedKeyFileField keyFile={generated} id="new-vault-key" onGenerate={() => void makeKeyFile()} />
              </div>
            ) : null}
            {keyFileMode === 'choose' ? (
              <div className="pl-6">
                <KeyFileInput value={keyFile} onChange={setKeyFile} />
              </div>
            ) : null}
          </fieldset>
          <div className="flex items-start gap-2">
            <Checkbox id="vault-remember" checked={remember} onCheckedChange={(v) => setRemember(v === true)} />
            <div className="space-y-0.5">
              <Label htmlFor="vault-remember">{t('unlock.remember')}</Label>
              <p className="text-xs text-muted-foreground">{t('unlock.rememberDescription')}</p>
            </div>
          </div>
          </>
          )}
          {problem === 'noKey' ? <p className="text-xs text-muted-foreground">{t('vaults.needsKey')}</p> : null}
          {problem === 'mismatch' && !confirm ? <p className="text-xs text-muted-foreground">{t('vaults.repeatPassword')}</p> : null}
          {problem === 'saveKeyFile' || problem === 'chooseKeyFile' ? (
            <p className="text-xs text-muted-foreground" data-testid="new-vault-problem">
              {t(`changeKey.problem.${problem}`)}
            </p>
          ) : null}
          {error ? <Alert variant="error">{error}</Alert> : null}
          {unkept ? <VaultKeyShown value={unkept.key} warning={t('vaultKey.notKeptDescription')} /> : null}
          {unkept ? (
            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => finish(unkept.fileId)} disabled={pending}>
                {t('vaultKey.saved')}
              </Button>
              {unkept.sealed ? (
                <Button type="button" loading={pending} onClick={() => void keepAgain()}>
                  {t('vaultKey.keepAgain')}
                </Button>
              ) : null}
            </DialogFooter>
          ) : (
            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => onOpenChange(false)} disabled={pending}>
                {t('common.cancel')}
              </Button>
              <Button type="submit" loading={pending} disabled={!folder || !name.trim() || problem !== null || madeFolder !== null}>
                {t('vaults.create')}
              </Button>
            </DialogFooter>
          )}
        </form>
        <NameDialog
          open={naming}
          title={t('vaults.newFolderTitle')}
          description={choice ? t('vaults.newFolderIn', { path: choice.path }) : undefined}
          initial=""
          submit={t('vaults.newFolderCreate')}
          pending={createFolder.isPending}
          error={createFolder.error}
          taken={taken}
          onClose={() => {
            setNaming(false)
            createFolder.reset()
          }}
          onSubmit={(folderName) => {
            if (!folder) return
            // Made under the chosen folder, then chosen: subfolders at any depth.
            createFolder.mutate(
              { parent: folder, name: folderName },
              {
                onSuccess: (id) => {
                  setNaming(false)
                  setMadeFolder(id)
                },
              },
            )
          }}
        />
      </DialogContent>
    </Dialog>
  )
}
