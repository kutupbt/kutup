import { FileUp } from 'lucide-react'
import { useEffect, useMemo, useRef, useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'
import { toast } from 'sonner'
import { loadServerSettings } from '@kutup/session/apps'
import { useRequiredSession } from '@kutup/session/store'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Checkbox } from '@kutup/ui/components/checkbox'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { Field } from '@kutup/ui/components/field'
import { Label } from '@kutup/ui/components/label'
import { PasswordInput } from '@kutup/ui/components/password-input'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@kutup/ui/components/select'
import { formatBytes } from '@kutup/ui/lib/format'
import { putKeptKey, sealVaultKey, secretsKey } from '../drive/secrets'
import { useCreateVaultFile, useVaultFiles } from '../drive/vaults'
import { freshKeys } from '../sync/openVaults'
import { probeVault, VaultError, VaultHandle, type VaultProbe } from '../vault/client'
import { KeyFileInput } from './KeyFileInput'

/** The first value of the administrators' setting, until the server's is read. */
const DEFAULT_MAX_BYTES = 64 * 1024 * 1024

type Chosen = { name: string; contents: Uint8Array; probe: VaultProbe }

/**
 * Brings an existing KeePass vault (from KeePassXC, a backup, another
 * device) into Kutup Pass: into a Drive folder, checked first that its key
 * opens it here, then kept in the account like a new vault's (by default).
 * The file is stored as it is; one older than KDBX 4.1 is upgraded at its
 * first change, and said so.
 */
export function UploadVaultDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const { t, i18n } = useTranslation()
  const navigate = useNavigate()
  const session = useRequiredSession()
  const queryClient = useQueryClient()
  const { folders, root } = useVaultFiles()
  const createFile = useCreateVaultFile()
  const input = useRef<HTMLInputElement>(null)
  const [maxBytes, setMaxBytes] = useState(DEFAULT_MAX_BYTES)
  const [chosen, setChosen] = useState<Chosen | null>(null)
  const [folderId, setFolderId] = useState('')
  const [password, setPassword] = useState('')
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
    setChosen(null)
    setFolderId('')
    setPassword('')
    setKeyFile(null)
    setRemember(true)
    setError(null)
    void loadServerSettings<{ passVaultMaxBytes?: number }>()
      .then((settings) => {
        if (typeof settings.passVaultMaxBytes === 'number') setMaxBytes(settings.passVaultMaxBytes)
      })
      .catch(() => undefined)
  }, [open])

  const folder = writable.find((f) => f.id === (folderId || root?.id))

  /** A file chosen: its name says KeePass, its size fits, its header says Kutup opens it. */
  const choose = async (file: File | undefined) => {
    setError(null)
    setChosen(null)
    if (!file) return
    if (!/\.kdbx$/i.test(file.name)) {
      setError(t('upload.notKdbx'))
      return
    }
    if (file.size > maxBytes) {
      setError(t('upload.tooLarge', { size: formatBytes(maxBytes, i18n.language) }))
      return
    }
    const contents = new Uint8Array(await file.arrayBuffer())
    const probe = await probeVault(contents)
    if (probe.kind === 'notKeePass') {
      setError(t('upload.notKeePass'))
      return
    }
    if (probe.kind === 'unsupported') {
      setError(probe.version.startsWith('1.') ? t('upload.keepass1') : t('upload.unsupportedVersion', { version: probe.version }))
      return
    }
    setChosen({ name: file.name.replace(/\.kdbx$/i, ''), contents, probe })
  }

  const submit = async () => {
    if (!chosen || !folder || (!password && !keyFile)) return
    setPending(true)
    setError(null)
    const key = { password: password || null, keyFile: keyFile?.contents ?? null }
    let handle: VaultHandle | null = null
    try {
      try {
        handle = await VaultHandle.open(chosen.contents, key)
      } catch (failure) {
        setError(openFailure(failure))
        return
      }
      const fileId = await createFile(folder, chosen.name, chosen.contents)
      if (remember) {
        try {
          await putKeptKey(session, fileId, await sealVaultKey(session, fileId, handle, 0, false))
          await queryClient.invalidateQueries({ queryKey: secretsKey })
        } catch {
          toast.error(t('unlock.keepFailed'))
        }
      }
      freshKeys.set(fileId, key)
      toast.success(t('upload.done'))
      onOpenChange(false)
      void navigate(`/v/${fileId}`)
    } catch {
      setError(t('upload.failed'))
    } finally {
      await handle?.close().catch(() => undefined)
      setPending(false)
    }
  }

  function openFailure(failure: unknown): string {
    if (!(failure instanceof VaultError)) return t('upload.failed')
    switch (failure.failure) {
      case 'wrongKey':
        return t('upload.wrongKey')
      case 'unsupported':
        return t('upload.unsupportedSettings')
      case 'damaged':
        return t('upload.damaged')
      case 'keyFile':
        return t('upload.keyFile')
      default:
        return t('upload.failed')
    }
  }

  const ready = Boolean(chosen && folder && (password || keyFile))
  return (
    <Dialog open={open} onOpenChange={(next) => !pending && onOpenChange(next)}>
      <DialogContent data-testid="vault-upload-dialog">
        <DialogHeader>
          <DialogTitle>{t('upload.title')}</DialogTitle>
          <DialogDescription>{t('upload.description')}</DialogDescription>
        </DialogHeader>
        <form
          className="mt-2 space-y-4"
          onSubmit={(e) => {
            e.preventDefault()
            void submit()
          }}
        >
          <div className="space-y-1.5">
            <span className="text-sm font-medium">{t('upload.file')}</span>
            <div className="flex items-center gap-2">
              <input
                ref={input}
                type="file"
                accept=".kdbx"
                className="hidden"
                onChange={(e) => void choose(e.target.files?.[0])}
                data-testid="vault-upload-file"
              />
              <Button type="button" variant="outline" onClick={() => input.current?.click()} disabled={pending}>
                <FileUp />
                {t('upload.choose')}
              </Button>
              <span className="min-w-0 truncate text-sm text-muted-foreground">{chosen ? `${chosen.name}.kdbx` : t('upload.none')}</span>
            </div>
            <p className="text-xs text-muted-foreground">{t('upload.limit', { size: formatBytes(maxBytes, i18n.language) })}</p>
          </div>
          {chosen?.probe.kind === 'supported' && chosen.probe.upgrade ? (
            <Alert variant="info" data-testid="vault-upload-upgrade">
              {t('upload.upgrade', { version: chosen.probe.version })}
            </Alert>
          ) : null}
          <Field label={t('vaults.folder')}>
            {(field) => (
              <Select value={folder?.id ?? ''} onValueChange={setFolderId}>
                <SelectTrigger id={field.id}>
                  <SelectValue placeholder={t('vaultMenu.chooseFolder')} />
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
          <Field label={t('upload.password')} description={t('upload.passwordDescription')}>
            {(field) => (
              <PasswordInput {...field} value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" data-testid="vault-upload-password" />
            )}
          </Field>
          <div className="space-y-1.5">
            <span className="text-sm font-medium">{t('keyFile.label')}</span>
            <KeyFileInput value={keyFile} onChange={setKeyFile} />
          </div>
          <div className="flex items-start gap-2">
            <Checkbox id="vault-upload-remember" checked={remember} onCheckedChange={(v) => setRemember(v === true)} />
            <div className="space-y-0.5">
              <Label htmlFor="vault-upload-remember">{t('unlock.remember')}</Label>
              <p className="text-xs text-muted-foreground">{t('unlock.rememberDescription')}</p>
            </div>
          </div>
          {error ? (
            <Alert variant="error" data-testid="vault-upload-error">
              {error}
            </Alert>
          ) : null}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)} disabled={pending}>
              {t('common.cancel')}
            </Button>
            <Button type="submit" loading={pending} disabled={!ready} data-testid="vault-upload-submit">
              {t('upload.submit')}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
