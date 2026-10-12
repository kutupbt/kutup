import { zodResolver } from '@hookform/resolvers/zod'
import { useQuery } from '@tanstack/react-query'
import { useForm } from 'react-hook-form'
import { useTranslation } from 'react-i18next'
import { Link, Navigate, useNavigate, useSearchParams } from 'react-router-dom'
import { z } from 'zod'
import api from '@kutup/session/client'
import { sanitizeNext } from '@kutup/session/sessionSync'
import { useSession } from '@kutup/session/store'
import { Alert } from '@kutup/ui/components/alert'
import { Field } from '@kutup/ui/components/field'
import { Input } from '@kutup/ui/components/input'
import { LoadingPanel } from '@kutup/ui/components/states'
import { AuthLayout } from './AuthLayout'
import { registerAndSignIn } from './flows'
import { NewKeysWizard } from './NewKeysWizard'

/** Mirrors the server's username rule (3–32 of a–z, 0–9, _ and -). */
const USERNAME = /^[a-z0-9_-]{3,32}$/

export function RegisterPage() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const [params] = useSearchParams()
  const next = sanitizeNext(params.get('next')) ?? '/'
  const session = useSession()
  const settings = useQuery({
    queryKey: ['public-settings'],
    queryFn: async () => (await api.get<{ registrationEnabled: boolean }>('/auth/settings')).data,
  })

  const schema = z.object({
    username: z.string().trim().regex(USERNAME, t('auth.validation.username')),
  })
  const {
    register,
    trigger,
    getValues,
    formState: { errors },
  } = useForm<z.infer<typeof schema>>({
    resolver: zodResolver(schema),
    defaultValues: { username: '' },
  })

  if (session) return <Navigate to={next} replace />
  if (settings.isPending) return <LoadingPanel label={t('common.loading')} />
  if (settings.data && !settings.data.registrationEnabled) {
    return (
      <AuthLayout title={t('register.closedTitle')} description={t('register.closedDescription')}>
        <Link to="/login" className="block text-center text-sm font-medium text-primary hover:underline">
          {t('register.backToSignIn')}
        </Link>
      </AuthLayout>
    )
  }

  return (
    <NewKeysWizard
      title={t('register.title')}
      description={t('register.description')}
      account={() => getValues('username').trim()}
      validateLeading={() => trigger()}
      leadingFields={
        <>
          <Field
            label={t('auth.fields.username')}
            error={errors.username?.message}
            description={t('register.usernameHint')}
            required
          >
            {(field) => (
              <Input {...field} {...register('username')} autoComplete="username" autoCapitalize="off" spellCheck={false} autoFocus />
            )}
          </Field>
          {settings.isError ? <Alert variant="warn">{t('register.settingsUnavailable')}</Alert> : null}
        </>
      }
      onKeysConfirmed={async (keys) => {
        await registerAndSignIn(getValues('username').trim(), keys)
        void navigate(next, { replace: true })
      }}
    />
  )
}
