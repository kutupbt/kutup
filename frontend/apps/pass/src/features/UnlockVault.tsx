import { LockKeyhole } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { ReauthLockedError, verifyAccountPassword } from '@kutup/session/reauth'
import { signOut } from '@kutup/session/signOut'
import { useRequiredSession } from '@kutup/session/store'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Checkbox } from '@kutup/ui/components/checkbox'
import { Field } from '@kutup/ui/components/field'
import { Label } from '@kutup/ui/components/label'
import { PasswordInput } from '@kutup/ui/components/password-input'
import { LoadingPanel } from '@kutup/ui/components/states'
import { keptKey, useKeepVaultKey, useVaultSecrets } from '../drive/secrets'
import { vaultTitle, type VaultFile } from '../drive/vaults'
import { setUnlockMode, unlockMode, type UnlockMode } from '../sync/autoLock'
import { isPin, PIN_LENGTH, verifyPin } from '../sync/pin'
import { clearLocked, freshKeys, openVault, wasLocked } from '../sync/openVaults'
import { VaultError } from '../vault/client'
import type { VaultKeyInput } from '../vault/types'
import { KeyFileInput } from './KeyFileInput'

type Attempt = 'trying' | 'form'

/** A vault locked in this tab, its key kept: the account password again, the PIN, or a click. */
function KeptUnlock({
  mode,
  pending,
  secret,
  setSecret,
  onUnlock,
}: {
  mode: UnlockMode
  pending: boolean
  /** The account password or the PIN, as typed. */
  secret: string
  setSecret: (value: string) => void
  onUnlock: (secret: string) => void
}) {
  const { t } = useTranslation()
  return (
    <div className="space-y-2">
      {mode === 'password' ? (
        <form
          className="space-y-2"
          onSubmit={(e) => {
            e.preventDefault()
            if (secret) onUnlock(secret)
          }}
        >
          <Field label={t('unlock.accountPassword')} description={t('unlock.accountPasswordDescription')}>
            {(field) => <PasswordInput {...field} value={secret} onChange={(e) => setSecret(e.target.value)} autoComplete="current-password" autoFocus />}
          </Field>
          <Button type="submit" className="w-full" loading={pending} disabled={!secret}>
            {t('unlock.withPassword')}
          </Button>
        </form>
      ) : mode === 'pin' ? (
        <form
          className="space-y-2"
          onSubmit={(e) => {
            e.preventDefault()
            if (isPin(secret)) onUnlock(secret)
          }}
        >
          <Field label={t('unlock.pin')} description={t('unlock.pinDescription')}>
            {(field) => (
              <PasswordInput
                {...field}
                value={secret}
                inputMode="numeric"
                autoComplete="off"
                maxLength={PIN_LENGTH}
                className="text-center font-mono tracking-[0.5em]"
                disabled={pending}
                autoFocus
                onChange={(e) => {
                  const digits = e.target.value.replace(/\D/g, '').slice(0, PIN_LENGTH)
                  setSecret(digits)
                  // As Proton Pass: the sixth digit sends it.
                  if (isPin(digits) && !pending) onUnlock(digits)
                }}
              />
            )}
          </Field>
          <Button type="submit" className="w-full" loading={pending} disabled={!isPin(secret)}>
            {t('unlock.withPin')}
          </Button>
        </form>
      ) : (
        <Button className="w-full" loading={pending} onClick={() => onUnlock('')}>
          {t('unlock.withSignIn')}
        </Button>
      )}
      <p className="text-center text-xs text-muted-foreground">{t('unlock.orKey')}</p>
    </div>
  )
}

/**
 * Opens a vault: with the key the account keeps for it (the Kutup sign-in),
 * else with what the person types, offering to keep that.
 */
export function UnlockVault({ vault }: { vault: VaultFile }) {
  const { t } = useTranslation()
  const session = useRequiredSession()
  const secrets = useVaultSecrets()
  const keepKey = useKeepVaultKey()
  const [attempt, setAttempt] = useState<Attempt>('trying')
  const [notice, setNotice] = useState<string | null>(null)
  const [password, setPassword] = useState('')
  const [keyFile, setKeyFile] = useState<{ name: string; contents: Uint8Array } | null>(null)
  const [remember, setRemember] = useState(true)
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [kept, setKept] = useState<VaultKeyInput | null>(null)
  const [keptSecret, setKeptSecret] = useState('')
  const [mode, setMode] = useState<UnlockMode>(unlockMode)
  const tried = useRef<string | null>(null)

  const fileId = vault.file.id
  useEffect(() => {
    if (secrets.isPending || tried.current === fileId) return
    tried.current = fileId
    setAttempt('trying')
    void (async () => {
      const fresh = freshKeys.get(fileId)
      const key = fresh ?? (await keptKey(session, secrets.data, fileId))
      if (!key) {
        setAttempt('form')
        return
      }
      // Locked in this tab: the kept key waits for a click.
      if (!fresh && wasLocked(fileId)) {
        setKept(key)
        setAttempt('form')
        return
      }
      try {
        await openVault(vault, key, session.userId)
        freshKeys.delete(fileId)
        clearLocked(fileId)
      } catch (failure) {
        setNotice(failure instanceof VaultError ? t('unlock.keptStale') : t('unlock.unreachable'))
        setAttempt('form')
      }
    })()
  }, [fileId, secrets.isPending, secrets.data, session, vault, t])

  const submit = async () => {
    const key: VaultKeyInput = { password: password || null, keyFile: keyFile?.contents ?? null }
    if (!key.password && !key.keyFile) return
    setPending(true)
    setError(null)
    try {
      await openVault(vault, key, session.userId)
      clearLocked(fileId)
      if (remember) {
        try {
          await keepKey(session, fileId, key)
        } catch {
          toast.error(t('unlock.keepFailed'))
        }
      }
    } catch (failure) {
      setError(failure instanceof VaultError ? t('unlock.wrongKey') : t('unlock.unreachable'))
    } finally {
      setPending(false)
    }
  }

  if (attempt === 'trying') return <LoadingPanel label={t('unlock.opening')} />
  return (
    <div className="mx-auto flex w-full max-w-md flex-col gap-6 px-4 py-10">
      <div className="flex flex-col items-center gap-3 text-center">
        <span className="grid size-12 place-items-center rounded-full bg-primary/10 text-primary">
          <LockKeyhole className="size-6" aria-hidden />
        </span>
        <h1 className="font-display text-xl font-semibold tracking-tight">{t('unlock.title', { name: vaultTitle(vault.file.name) })}</h1>
        <p className="text-sm text-muted-foreground">{t('unlock.description')}</p>
      </div>
      {notice ? <Alert variant="warn">{notice}</Alert> : null}
      {kept ? (
        <KeptUnlock
          mode={mode}
          pending={pending}
          secret={keptSecret}
          setSecret={setKeptSecret}
          onUnlock={(secret) => {
            setPending(true)
            setError(null)
            void (async () => {
              try {
                if (mode === 'password' && !(await verifyAccountPassword(secret))) {
                  setError(t('unlock.wrongAccountPassword'))
                  return
                }
                if (mode === 'pin') {
                  const check = await verifyPin(secret)
                  if (check.result === 'wrong') {
                    setError(t('unlock.wrongPin', { count: check.attemptsLeft }))
                    return
                  }
                  if (check.result === 'signedOut') {
                    toast.error(t('unlock.pinSignedOut'))
                    await signOut()
                    return
                  }
                  if (check.result === 'noPin') {
                    // Removed, perhaps on another device: the password again.
                    setUnlockMode('password')
                    setMode('password')
                    setError(t('unlock.pinRemoved'))
                    return
                  }
                }
                await openVault(vault, kept, session.userId)
                clearLocked(fileId)
              } catch (failure) {
                setError(
                  failure instanceof ReauthLockedError
                    ? t(failure.reason === 'rateLimited' ? 'unlock.slowDown' : 'unlock.paused')
                    : failure instanceof VaultError
                      ? t('unlock.keptStale')
                      : t('unlock.checkUnreachable'),
                )
              } finally {
                setKeptSecret('')
                setPending(false)
              }
            })()
          }}
        />
      ) : null}
      <form
        className="space-y-4"
        onSubmit={(e) => {
          e.preventDefault()
          void submit()
        }}
      >
        <Field label={t('vaults.password')}>
          {(field) => (
            <PasswordInput {...field} value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" autoFocus />
          )}
        </Field>
        <div className="space-y-1.5">
          <span className="text-sm font-medium">{t('keyFile.label')}</span>
          <KeyFileInput value={keyFile} onChange={setKeyFile} />
        </div>
        <div className="flex items-start gap-2">
          <Checkbox id="unlock-remember" checked={remember} onCheckedChange={(v) => setRemember(v === true)} />
          <div className="space-y-0.5">
            <Label htmlFor="unlock-remember">{t('unlock.remember')}</Label>
            <p className="text-xs text-muted-foreground">{t('unlock.rememberDescription')}</p>
          </div>
        </div>
        {error ? <Alert variant="error">{error}</Alert> : null}
        <Button type="submit" className="w-full" loading={pending} disabled={!password && !keyFile}>
          {t('unlock.submit')}
        </Button>
      </form>
    </div>
  )
}
