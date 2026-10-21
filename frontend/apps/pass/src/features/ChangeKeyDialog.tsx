import { Download, Wand2 } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { deleteVersion, listVersions } from '@kutup/collab/api'
import { useRequiredSession } from '@kutup/session/store'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Checkbox } from '@kutup/ui/components/checkbox'
import { ConfirmDestructive } from '@kutup/ui/components/confirm-destructive'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { Field } from '@kutup/ui/components/field'
import { Label } from '@kutup/ui/components/label'
import { PasswordInput } from '@kutup/ui/components/password-input'
import { forgetVaultKey, keepVaultKey, keptGeneratedPassword, keptKeyKind, secretsKey, useVaultSecrets } from '../drive/secrets'
import type { VaultFile } from '../drive/vaults'
import { randomVaultKey, strengthOf } from '../lib/generator'
import {
  keyChangeProblem,
  keyFileChoices,
  keyFileName,
  passwordChoices,
  type KeyChangeForm,
  type KeyFileChoice,
  type KeyParts,
  type PasswordChoice,
} from '../lib/keyChange'
import { useSessionState } from '../sync/openVaults'
import { KeyChangeError, type VaultSession } from '../sync/vaultSession'
import { generateKeyFile, type KeyChanged } from '../vault/client'
import { KeyFileInput } from './KeyFileInput'

/** Saves `contents` as a download named `name`; the bytes go nowhere else. */
function download(contents: Uint8Array, name: string) {
  const url = URL.createObjectURL(new Blob([contents as BlobPart], { type: 'application/octet-stream' }))
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
 * Changes a vault's key (docs/plans/pass-parity.md, "Change the vault's
 * key"), as KeePassXC's database key settings do: the password kept,
 * changed or removed, a key file kept, generated (KeePassXC's XML v2,
 * downloaded once, never sent anywhere), chosen or removed; one part at
 * least. The vault is saved with it straight to Drive, or nothing changes;
 * then the new key is kept in the account (or the old one forgotten), and
 * the owner may delete the earlier versions, which still open with the old
 * key.
 */
export function ChangeKeyDialog({
  open,
  onOpenChange,
  session,
  vault,
  title,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  session: VaultSession
  vault: VaultFile
  title: string
}) {
  const { t } = useTranslation()
  const signedIn = useRequiredSession()
  const secrets = useVaultSecrets()
  const queryClient = useQueryClient()
  const state = useSessionState(session)
  const fileId = vault.file.id
  const [now, setNow] = useState<KeyParts | null>(null)
  const [wasKept, setWasKept] = useState(false)
  const [keptGenerated, setKeptGenerated] = useState(false)
  const [password, setPassword] = useState<PasswordChoice>('keep')
  const [newPassword, setNewPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [madePassword, setMadePassword] = useState<string | null>(null)
  const [keyFile, setKeyFile] = useState<KeyFileChoice>('keep')
  const generated = useRef<Uint8Array | null>(null)
  const [hasGenerated, setHasGenerated] = useState(false)
  const [generatedSaved, setGeneratedSaved] = useState(false)
  const [chosen, setChosen] = useState<{ name: string; contents: Uint8Array } | null>(null)
  const [remember, setRemember] = useState(true)
  const [dropVersions, setDropVersions] = useState(false)
  const [confirming, setConfirming] = useState(false)
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [pendingNotice, setPendingNotice] = useState(false)
  const owner = vault.folder.source === 'owned' && vault.folder.ownerUserId === signedIn.userId

  // A generated key file lives only here, and is wiped when the dialog goes.
  const forgetGenerated = () => {
    generated.current?.fill(0)
    generated.current = null
    setHasGenerated(false)
    setGeneratedSaved(false)
  }

  useEffect(() => {
    if (!open) {
      forgetGenerated()
      return
    }
    let current = true
    setNow(null)
    setError(null)
    setNewPassword('')
    setConfirm('')
    setMadePassword(null)
    setChosen(null)
    setDropVersions(false)
    setPendingNotice(false)
    void (async () => {
      const parts = await session.vault().keyParts()
      const kind = await keptKeyKind(signedIn, secrets.data, fileId).catch(() => 'unknown' as const)
      if (!current) return
      setNow(parts)
      setPassword(passwordChoices(parts)[0])
      setKeyFile(keyFileChoices(parts)[0])
      setWasKept(kind !== 'none')
      setRemember(kind !== 'none')
      setKeptGenerated(kind === 'generated' || kind === 'unknown')
    })()
    return () => {
      current = false
    }
    // Read once per opening.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open])

  const form: KeyChangeForm | null = now
    ? { now, password, newPassword, confirm, keyFile, generated: hasGenerated, generatedSaved, chosen: chosen !== null }
    : null
  const problem = form ? keyChangeProblem(form) : 'unchanged'
  const saved = state?.status === 'saved'

  const makeKeyFile = async () => {
    try {
      forgetGenerated()
      const file = await generateKeyFile()
      generated.current = file
      setHasGenerated(true)
      download(file, keyFileName(title))
    } catch {
      setError(t('changeKey.generateFailed'))
    }
  }

  const change = async () => {
    // The same rules as the button: Enter never gets past them.
    if (!form || keyChangeProblem(form) !== null || !saved || pending || pendingNotice) return
    setPending(true)
    setError(null)
    try {
      // A password Kasa generated and kept, kept: offered as it is, so it
      // stays one that can be shown. The worker takes it only if it is the
      // vault's password now (a stale kept copy never replaces it).
      const keptPassword = password === 'keep' && keptGenerated ? await keptGeneratedPassword(signedIn, secrets.data, fileId).catch(() => null) : null
      // What the account keeps follows the vault's new key, as chosen:
      // now, or once a save that got no answer has reached Drive.
      const keepChoice = async (done: KeyChanged) => {
        if (remember) await keepVaultKey(signedIn, fileId, session.vault(), password === 'new' ? newPassword === madePassword : password === 'keep' && done.passwordShowable)
        else if (wasKept) await forgetVaultKey(signedIn, fileId)
        await queryClient.invalidateQueries({ queryKey: secretsKey })
      }
      const deleteVersions = dropVersions && owner
      // What follows a key change only once Drive has the vault under it.
      const afterSaved = async (done: KeyChanged) => {
        await keepChoice(done).catch(() => toast.warning(t('changeKey.keepFailed')))
        if (deleteVersions) {
          const left = await deleteEarlierVersions(fileId)
          if (left > 0) toast.warning(t('changeKey.versionsLeft', { count: left }))
        }
      }
      let changed
      try {
        changed = await session.changeKey({
          password: password === 'keep' ? 'keep' : password === 'new' ? { set: newPassword } : null,
          shownPassword: keptPassword,
          keyFile: keyFile === 'keep' ? 'keep' : keyFile === 'generate' ? generated.current : keyFile === 'choose' ? (chosen?.contents ?? null) : null,
        }, afterSaved)
      } catch (failure) {
        if (failure instanceof KeyChangeError && failure.failure === 'pending') {
          // The new key stays and is saved once Kutup answers; the kept key
          // (and the earlier versions' deletion) follow then, or at the next
          // unlock if this tab closes first.
          forgetGenerated()
          if (password === 'new' && newPassword === madePassword) {
            // A generated password exists only here until then: shown, to
            // copy now, before the dialog goes.
            setPendingNotice(true)
            return
          }
          toast.warning(t('changeKey.failure.pending'))
          onOpenChange(false)
          return
        }
        setError(failure instanceof KeyChangeError ? t(`changeKey.failure.${failure.failure}`) : t('changeKey.failure.failed'))
        return
      }
      let keepFailed = false
      try {
        await keepChoice(changed)
      } catch {
        keepFailed = true
      }
      let versionsLeft = 0
      if (deleteVersions) versionsLeft = await deleteEarlierVersions(fileId)
      forgetGenerated()
      if (keepFailed) toast.warning(t('changeKey.keepFailed'))
      if (versionsLeft > 0) toast.warning(t('changeKey.versionsLeft', { count: versionsLeft }))
      toast.success(t('changeKey.done'))
      onOpenChange(false)
    } finally {
      setPending(false)
    }
  }

  const submit = () => {
    if (!form || keyChangeProblem(form) !== null || !saved) return
    if (dropVersions && owner) setConfirming(true)
    else void change()
  }

  return (
    <>
      <Dialog open={open} onOpenChange={(next) => !pending && onOpenChange(next)}>
        <DialogContent className="max-h-[90vh] overflow-y-auto" data-testid="change-key-dialog">
          <DialogHeader>
            <DialogTitle>{t('changeKey.title', { name: title })}</DialogTitle>
            <DialogDescription>{t('changeKey.description')}</DialogDescription>
          </DialogHeader>
          {now === null ? null : (
            <form
              className="mt-2 space-y-4"
              onSubmit={(e) => {
                e.preventDefault()
                submit()
              }}
            >
              <p className="text-sm" data-testid="change-key-now">
                {t(now.password && now.keyFile ? 'changeKey.nowBoth' : now.password ? 'changeKey.nowPassword' : 'changeKey.nowKeyFile')}
              </p>
              <fieldset className="space-y-2">
                <legend className="text-sm font-medium">{t('changeKey.password')}</legend>
                {passwordChoices(now).map((value) => (
                  <label key={value} className="flex items-center gap-2 text-sm">
                    <input type="radio" name="change-key-password" checked={password === value} onChange={() => setPassword(value)} />
                    {t(`changeKey.passwordChoice.${value}`)}
                  </label>
                ))}
                {password === 'new' ? (
                  <div className="space-y-3 pl-6">
                    <Field label={t('changeKey.newPassword')} description={newPassword ? t(`strength.${strengthOf(newPassword)}`) : undefined}>
                      {(field) => <PasswordInput {...field} value={newPassword} onChange={(e) => setNewPassword(e.target.value)} autoComplete="new-password" />}
                    </Field>
                    <Field label={t('changeKey.confirmPassword')} error={confirm && confirm !== newPassword ? t('vaults.mismatch') : undefined}>
                      {(field) => <PasswordInput {...field} value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="new-password" />}
                    </Field>
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      onClick={() => {
                        const made = randomVaultKey()
                        setMadePassword(made)
                        setNewPassword(made)
                        setConfirm(made)
                      }}
                    >
                      <Wand2 />
                      {t('changeKey.generatePassword')}
                    </Button>
                  </div>
                ) : null}
              </fieldset>
              <fieldset className="space-y-2">
                <legend className="text-sm font-medium">{t('changeKey.keyFile')}</legend>
                {keyFileChoices(now).map((value) => (
                  <label key={value} className="flex items-center gap-2 text-sm">
                    <input type="radio" name="change-key-file" checked={keyFile === value} onChange={() => setKeyFile(value)} />
                    {t(`changeKey.keyFileChoice.${value}`)}
                  </label>
                ))}
                {keyFile === 'generate' ? (
                  <div className="space-y-2 pl-6">
                    <Button type="button" variant="outline" size="sm" onClick={() => void makeKeyFile()} data-testid="change-key-generate">
                      <Download />
                      {hasGenerated ? t('changeKey.downloadAgain') : t('changeKey.generateKeyFile')}
                    </Button>
                    {hasGenerated ? (
                      <div className="flex items-start gap-2">
                        <Checkbox id="change-key-saved" checked={generatedSaved} onCheckedChange={(v) => setGeneratedSaved(v === true)} />
                        <Label htmlFor="change-key-saved" className="text-sm font-normal">
                          {t('changeKey.keyFileSaved', { name: keyFileName(title) })}
                        </Label>
                      </div>
                    ) : null}
                  </div>
                ) : null}
                {keyFile === 'choose' ? (
                  <div className="pl-6">
                    <KeyFileInput value={chosen} onChange={setChosen} />
                  </div>
                ) : null}
              </fieldset>
              <Alert variant="warn">
                <p>{t('changeKey.othersNeedIt')}</p>
                <p className="mt-1">{t('changeKey.earlierVersions')}</p>
              </Alert>
              <div className="flex items-start gap-2">
                <Checkbox id="change-key-remember" checked={remember} onCheckedChange={(v) => setRemember(v === true)} />
                <div className="space-y-0.5">
                  <Label htmlFor="change-key-remember">{t('unlock.remember')}</Label>
                  <p className="text-xs text-muted-foreground">{t('unlock.rememberDescription')}</p>
                </div>
              </div>
              {owner ? (
                <div className="flex items-start gap-2">
                  <Checkbox id="change-key-versions" checked={dropVersions} onCheckedChange={(v) => setDropVersions(v === true)} />
                  <div className="space-y-0.5">
                    <Label htmlFor="change-key-versions">{t('changeKey.deleteVersions')}</Label>
                    <p className="text-xs text-muted-foreground">{t('changeKey.deleteVersionsDescription')}</p>
                  </div>
                </div>
              ) : null}
              {!saved ? <Alert variant="info">{t('changeKey.waitSaved')}</Alert> : null}
              {problem && problem !== 'unchanged' && problem !== 'emptyPassword' ? (
                <p className="text-xs text-muted-foreground" data-testid="change-key-problem">
                  {t(`changeKey.problem.${problem}`)}
                </p>
              ) : null}
              {error ? <Alert variant="error">{error}</Alert> : null}
              {pendingNotice ? (
                <Alert variant="warn" data-testid="change-key-pending">
                  {t('changeKey.pendingCopyPassword')}
                </Alert>
              ) : null}
              <DialogFooter>
                <Button type="button" variant="outline" onClick={() => onOpenChange(false)} disabled={pending}>
                  {t('common.cancel')}
                </Button>
                <Button type="submit" loading={pending} disabled={problem !== null || !saved || pendingNotice} data-testid="change-key-submit">
                  {t('changeKey.submit')}
                </Button>
              </DialogFooter>
            </form>
          )}
        </DialogContent>
      </Dialog>
      <ConfirmDestructive
        open={confirming}
        onOpenChange={setConfirming}
        title={t('changeKey.deleteVersionsTitle')}
        description={t('changeKey.deleteVersionsConfirm')}
        warning={t('changeKey.deleteVersionsWarning')}
        submit={t('changeKey.submitAndDelete')}
        errorFallback={t('changeKey.failure.failed')}
        onConfirm={() => {
          setConfirming(false)
          void change()
        }}
      />
    </>
  )
}

/**
 * Deletes every earlier version of the vault and its first upload, leaving
 * the version just saved under the new key. Returns how many could not be
 * deleted (each is tried; one already gone counts as deleted).
 */
async function deleteEarlierVersions(fileId: string): Promise<number> {
  let left = 0
  const versions = await listVersions(fileId).catch(() => null)
  if (!versions) return 1
  // Newest first: the first is the vault as just saved.
  for (const version of versions.slice(1)) {
    try {
      await deleteVersion(fileId, version.id)
    } catch {
      left += 1
    }
  }
  try {
    await deleteVersion(fileId, 'original')
  } catch (error) {
    const status = (error as { response?: { status?: number } }).response?.status
    if (status !== 404) left += 1
  }
  return left
}
