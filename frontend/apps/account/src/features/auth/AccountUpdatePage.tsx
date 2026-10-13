import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Navigate, useNavigate, useSearchParams } from 'react-router-dom'
import { sanitizeNext } from '@kutup/session/sessionSync'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Field } from '@kutup/ui/components/field'
import { Textarea } from '@kutup/ui/components/textarea'
import { toast } from 'sonner'
import { AuthLayout } from './AuthLayout'
import { newRecoveryPhrase, rebindAccount, WrongRecoveryPhrase, type RecoveryChoice } from './flows'
import { getPendingRebind, setPendingRebind } from './pendingRebind'
import { UnreadableVaultKeys } from '@kutup/session/passRebind'
import { ConfirmRecoveryPhrase, ShowRecoveryPhrase } from './RecoveryPhrase'

type Step = { kind: 'phrase' } | { kind: 'newShow'; mnemonic: string } | { kind: 'newConfirm'; mnemonic: string }

/**
 * Right after signing in to an account whose keys are still bound to its old
 * sign-in email: the keys move to the account's key binding, once, here in
 * the browser (docs/plans/account-identity.md). The recovery part needs the
 * 24 words: confirmed, or replaced by a new phrase shown and confirmed first.
 * "Later" keeps everything as it is until the next sign-in.
 */
export function AccountUpdatePage() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const [params] = useSearchParams()
  const next = sanitizeNext(params.get('next')) ?? '/'
  const [pendingRebind] = useState(getPendingRebind)
  const [step, setStep] = useState<Step>({ kind: 'phrase' })
  const [phrase, setPhrase] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  // Kept Pass vault keys that no longer open: the re-seal asks before forgetting them.
  const [unreadable, setUnreadable] = useState<{ count: number; choice: RecoveryChoice } | null>(null)
  if (!pendingRebind) return <Navigate to={next} replace />

  const finish = async (choice: RecoveryChoice) => {
    setError(null)
    setBusy(true)
    try {
      await rebindAccount(pendingRebind, choice)
      setPendingRebind(null)
      toast.success(t('rebind.done'))
      void navigate(next, { replace: true })
    } catch (err) {
      if (err instanceof UnreadableVaultKeys) setUnreadable({ count: err.count, choice })
      else setError(err instanceof WrongRecoveryPhrase ? t('rebind.wrongPhrase') : t('rebind.failed'))
    } finally {
      setBusy(false)
    }
  }
  const later = () => {
    setPendingRebind(null)
    void navigate(next, { replace: true })
  }

  if (unreadable) {
    return (
      <AuthLayout title={t('rebind.unreadableTitle')} description={t('rebind.unreadableDescription', { count: unreadable.count })} width="md">
        <div className="space-y-3">
          {error ? <Alert variant="error">{error}</Alert> : null}
          <Button
            className="w-full"
            loading={busy}
            onClick={() => {
              const choice = { ...unreadable.choice, forgetUnreadableVaultKeys: true }
              setUnreadable(null)
              void finish(choice)
            }}
          >
            {t('rebind.unreadableForget')}
          </Button>
          <Button variant="ghost" className="w-full" disabled={busy} onClick={later}>
            {t('rebind.later')}
          </Button>
        </div>
      </AuthLayout>
    )
  }

  if (step.kind === 'newShow') {
    return (
      <AuthLayout title={t('rebind.noPhraseTitle')} description={t('rebind.noPhraseDescription')} width="md">
        <ShowRecoveryPhrase mnemonic={step.mnemonic} account={pendingRebind.name} onContinue={() => setStep({ kind: 'newConfirm', mnemonic: step.mnemonic })} />
      </AuthLayout>
    )
  }
  if (step.kind === 'newConfirm') {
    return (
      <AuthLayout title={t('rebind.noPhraseTitle')} description={t('rebind.noPhraseDescription')} width="md">
        <ConfirmRecoveryPhrase
          mnemonic={step.mnemonic}
          pending={busy}
          error={error}
          onBack={() => setStep({ kind: 'newShow', mnemonic: step.mnemonic })}
          onConfirmed={() => void finish({ kind: 'new', mnemonic: step.mnemonic })}
        />
      </AuthLayout>
    )
  }

  return (
    <AuthLayout title={t('rebind.title')} description={t('rebind.description', { name: pendingRebind.name })} width="md">
      <form
        className="space-y-4"
        onSubmit={(event) => {
          event.preventDefault()
          void finish({ kind: 'phrase', mnemonic: phrase })
        }}
      >
        <Field label={t('rebind.phrase')} description={t('rebind.phraseHint')} required>
          {(field) => (
            <Textarea {...field} value={phrase} onChange={(e) => setPhrase(e.target.value)} rows={4} autoComplete="off" spellCheck={false} autoFocus className="font-mono" />
          )}
        </Field>
        {error ? <Alert variant="error">{error}</Alert> : null}
        <Button type="submit" className="w-full" loading={busy} disabled={!phrase.trim()}>
          {t('rebind.confirm')}
        </Button>
        <Button type="button" variant="link" className="w-full" disabled={busy} onClick={() => void newRecoveryPhrase().then((mnemonic) => setStep({ kind: 'newShow', mnemonic }))}>
          {t('rebind.noPhrase')}
        </Button>
        <div className="text-center">
          <Button type="button" variant="ghost" disabled={busy} onClick={later}>
            {t('rebind.later')}
          </Button>
          <p className="text-xs text-muted-foreground">{t('rebind.laterHint')}</p>
        </div>
      </form>
    </AuthLayout>
  )
}
