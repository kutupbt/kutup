import { zodResolver } from '@hookform/resolvers/zod'
import { useEffect, useState } from 'react'
import { useForm } from 'react-hook-form'
import { useTranslation } from 'react-i18next'
import { Link, Navigate, useNavigate, useSearchParams } from 'react-router-dom'
import { z } from 'zod'
import { OpaqueWorkerClosed } from '@kutup/crypto/opaqueWorker'
import { useSession } from '@kutup/session/store'
import { sanitizeNext } from '@kutup/session/sessionSync'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Field } from '@kutup/ui/components/field'
import { Input } from '@kutup/ui/components/input'
import { PasswordInput } from '@kutup/ui/components/password-input'
import { AuthLayout } from './AuthLayout'
import { authErrorMessage, bodyCode } from './errors'
import { abandonTotp, completeTotp, signIn, type TotpChallenge } from './flows'
import { setPendingSetup } from './pendingSetup'

/**
 * Sign-in: username (or Kutup address) + password, then a TOTP code when the
 * account has 2FA. The server answers a missing account and a wrong password
 * identically; the form does not try to tell them apart.
 */
export function LoginPage() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const [params] = useSearchParams()
  const next = sanitizeNext(params.get('next')) ?? '/'
  const session = useSession()
  const [challenge, setChallenge] = useState<TotpChallenge | null>(null)
  const [code, setCode] = useState('')
  // A recovery code in place of the authenticator's (Proton's "use a
  // recovery code"): the server takes either in the same field.
  const [recovery, setRecovery] = useState(false)
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<string | null>(
    // Sent back from a first sign-in whose setup token ran out.
    () => (params.get('setup') === 'expired' ? t('auth.errors.setupExpired') : null),
  )

  // A sign-in waiting for its code ends with this page, or when another
  // replaces it: its worker holds the password and the export key.
  useEffect(() => () => {
    if (challenge) abandonTotp(challenge)
  }, [challenge])

  const schema = z.object({
    name: z.string().trim().min(1, t('auth.validation.usernameRequired')),
    password: z.string().min(1, t('auth.validation.passwordRequired')),
  })
  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm<z.infer<typeof schema>>({
    resolver: zodResolver(schema),
    defaultValues: { name: '', password: '' },
  })

  if (session && !pending) return <Navigate to={next} replace />

  const signedIn = () => {
    void navigate(next, { replace: true })
  }

  const onCredentials = handleSubmit(async ({ name, password }) => {
    setError(null)
    setPending(true)
    try {
      const result = await signIn(name.trim(), password)
      if (result.kind === 'setup') {
        setPendingSetup(result.setup)
        void navigate(`/first-login?next=${encodeURIComponent(next)}`, { replace: true })
      } else if (result.kind === 'totp') {
        setChallenge(result.challenge)
      } else {
        signedIn()
      }
    } catch (err) {
      setError(authErrorMessage(err, t, 'auth.errors.signInFailed'))
    } finally {
      setPending(false)
    }
  })

  async function onTotp(event: React.FormEvent) {
    event.preventDefault()
    if (!challenge) return
    setError(null)
    setPending(true)
    try {
      const result = await completeTotp(challenge, code.trim())
      if (result.kind === 'signedIn') signedIn()
    } catch (err) {
      if (err instanceof OpaqueWorkerClosed || bodyCode(err) === 'preAuthInvalid') {
        // The sign-in itself ended (it failed after the code, its first step
        // expired, or the password changed meanwhile): start over.
        setChallenge(null)
        setCode('')
        setError(t('auth.errors.signInAgain'))
      } else {
        setError(authErrorMessage(err, t, 'auth.errors.totpFailed'))
      }
    } finally {
      setPending(false)
    }
  }

  if (challenge) {
    return (
      <AuthLayout
        title={t('login.totpTitle')}
        description={t(recovery ? 'login.recoveryCodeDescription' : 'login.totpDescription')}
      >
        <form className="space-y-4" onSubmit={(e) => void onTotp(e)}>
          <Field label={t(recovery ? 'login.recoveryCode' : 'login.totpCode')} required>
            {(field) => (
              <Input
                {...field}
                key={recovery ? 'recovery' : 'totp'}
                value={code}
                onChange={(e) => setCode(e.target.value)}
                autoComplete={recovery ? 'off' : 'one-time-code'}
                inputMode={recovery ? 'text' : 'numeric'}
                maxLength={recovery ? 13 : 6}
                spellCheck={false}
                className="font-mono tracking-widest"
                autoFocus
              />
            )}
          </Field>
          {error ? <Alert variant="error">{error}</Alert> : null}
          <Button type="submit" className="w-full" loading={pending}>
            {t('login.verify')}
          </Button>
          <Button
            type="button"
            variant="link"
            className="w-full"
            onClick={() => {
              setRecovery(!recovery)
              setCode('')
              setError(null)
            }}
          >
            {t(recovery ? 'login.useAuthenticator' : 'login.useRecoveryCode')}
          </Button>
          <Button
            type="button"
            variant="link"
            className="w-full"
            onClick={() => {
              abandonTotp(challenge)
              setChallenge(null)
              setCode('')
              setRecovery(false)
              setError(null)
            }}
          >
            {t('login.useAnotherAccount')}
          </Button>
        </form>
      </AuthLayout>
    )
  }

  return (
    <AuthLayout title={t('login.title')} description={t('login.description')}>
      <form className="space-y-4" onSubmit={(e) => void onCredentials(e)} noValidate>
        <Field label={t('auth.fields.username')} error={errors.name?.message} description={t('login.nameHint')} required>
          {(field) => (
            <Input {...field} {...register('name')} autoComplete="username" autoCapitalize="off" spellCheck={false} autoFocus />
          )}
        </Field>
        <Field label={t('auth.fields.password')} error={errors.password?.message} required>
          {(field) => (
            <PasswordInput {...field} {...register('password')} autoComplete="current-password" />
          )}
        </Field>
        {error ? <Alert variant="error">{error}</Alert> : null}
        <Button type="submit" className="w-full" loading={pending}>
          {pending ? t('login.unlocking') : t('login.submit')}
        </Button>
      </form>
      <div className="mt-6 flex flex-col items-center gap-2 text-sm">
        <Link to="/recover" className="text-muted-foreground underline-offset-4 hover:underline">
          {t('login.forgot')}
        </Link>
        <p className="text-muted-foreground">
          {t('login.noAccount')}{' '}
          <Link to={`/register?next=${encodeURIComponent(next)}`} className="font-medium text-primary underline-offset-4 hover:underline">
            {t('login.register')}
          </Link>
        </p>
      </div>
    </AuthLayout>
  )
}
