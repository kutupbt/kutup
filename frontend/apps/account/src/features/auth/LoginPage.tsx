import { zodResolver } from '@hookform/resolvers/zod'
import { useState } from 'react'
import { useForm } from 'react-hook-form'
import { useTranslation } from 'react-i18next'
import { Link, Navigate, useNavigate, useSearchParams } from 'react-router-dom'
import { z } from 'zod'
import { useSession } from '@kutup/session/store'
import { sanitizeNext } from '@kutup/session/sessionSync'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Field } from '@kutup/ui/components/field'
import { Input } from '@kutup/ui/components/input'
import { PasswordInput } from '@kutup/ui/components/password-input'
import { AuthLayout } from './AuthLayout'
import { authErrorMessage } from './errors'
import { completeTotp, signIn, type TotpChallenge } from './flows'
import { setPendingSetup } from './pendingSetup'

/**
 * Sign-in: email + password, then a TOTP code when the account has 2FA.
 * The server answers a missing account and a wrong password identically; the
 * form does not try to tell them apart.
 */
export function LoginPage() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const [params] = useSearchParams()
  const next = sanitizeNext(params.get('next')) ?? '/'
  const session = useSession()
  const [challenge, setChallenge] = useState<TotpChallenge | null>(null)
  const [code, setCode] = useState('')
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const schema = z.object({
    email: z.string().trim().min(1, t('auth.validation.emailRequired')),
    password: z.string().min(1, t('auth.validation.passwordRequired')),
  })
  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm<z.infer<typeof schema>>({
    resolver: zodResolver(schema),
    defaultValues: { email: '', password: '' },
  })

  if (session && !pending) return <Navigate to={next} replace />

  const onCredentials = handleSubmit(async ({ email, password }) => {
    setError(null)
    setPending(true)
    try {
      const result = await signIn(email.trim(), password)
      if (result.kind === 'setup') {
        setPendingSetup(result.setup)
        void navigate(`/first-login?next=${encodeURIComponent(next)}`, { replace: true })
      } else if (result.kind === 'totp') {
        setChallenge(result.challenge)
      } else {
        void navigate(next, { replace: true })
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
      await completeTotp(challenge, code.trim())
      void navigate(next, { replace: true })
    } catch (err) {
      setError(authErrorMessage(err, t, 'auth.errors.totpFailed'))
    } finally {
      setPending(false)
    }
  }

  if (challenge) {
    return (
      <AuthLayout title={t('login.totpTitle')} description={t('login.totpDescription')}>
        <form className="space-y-4" onSubmit={(e) => void onTotp(e)}>
          <Field label={t('login.totpCode')} required>
            {(field) => (
              <Input
                {...field}
                value={code}
                onChange={(e) => setCode(e.target.value)}
                autoComplete="one-time-code"
                inputMode="numeric"
                maxLength={6}
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
              challenge.keyEncryptionKey.fill(0)
              setChallenge(null)
              setCode('')
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
        <Field label={t('auth.fields.email')} error={errors.email?.message} required>
          {(field) => (
            <Input {...field} {...register('email')} type="email" autoComplete="username" autoFocus />
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
