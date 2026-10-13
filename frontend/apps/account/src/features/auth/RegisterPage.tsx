import { zodResolver } from '@hookform/resolvers/zod'
import { useQuery } from '@tanstack/react-query'
import { isAxiosError } from 'axios'
import { useEffect, useRef, useState } from 'react'
import { useForm } from 'react-hook-form'
import { useTranslation } from 'react-i18next'
import { Link, Navigate, useLocation, useNavigate, useSearchParams } from 'react-router-dom'
import { z } from 'zod'
import type { RegistrationMode } from '@kutup/session/api-types'
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

/** A referral code from a sign-up link (`/register#code=…`; in the fragment, so no server logs it). */
function codeFromLink(hash: string): string {
  return new URLSearchParams(hash.replace(/^#/, '')).get('code')?.trim() ?? ''
}

/** What the server said about a code, as the field says it. */
function codeProblem(error: unknown): string | null {
  if (!isAxiosError(error)) return null
  const code = (error.response?.data as { code?: string } | undefined)?.code
  return code === 'registrationCodeInvalid' || code === 'registrationCodeRequired' || code === 'rateLimited' || code === 'registrationClosed' ? code : null
}

export function RegisterPage() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const [params] = useSearchParams()
  const next = sanitizeNext(params.get('next')) ?? '/'
  const session = useSession()
  const location = useLocation()
  const settings = useQuery({
    queryKey: ['public-settings'],
    queryFn: async () => (await api.get<{ registrationMode: RegistrationMode }>('/auth/settings')).data,
  })
  const linked = codeFromLink(location.hash)
  const [code, setCode] = useState(linked)
  // In `on` mode the code field stays folded until asked for (or a link brought one).
  const [codeOpen, setCodeOpen] = useState(linked !== '')
  const [codeError, setCodeError] = useState<string | null>(null)
  // The server's answer for the code last checked, so leaving the field and
  // pressing Continue do not each spend a check (they are rate-limited).
  // The pending check counts too, so both at once still make one request.
  const checked = useRef<{ value: string; answer: Promise<string | null> } | null>(null)
  // The field's value now, for an answer that arrives after it changed.
  const current = useRef(code)
  current.current = code
  // A sign-up link (also one opened while the page is up) fills the field;
  // the code then leaves the address bar, its history entry and bookmarks.
  useEffect(() => {
    if (!linked) return
    setCode(linked)
    setCodeOpen(true)
    setCodeError(null)
    void navigate({ pathname: location.pathname, search: location.search }, { replace: true, state: location.state as unknown })
  }, [linked, navigate, location.pathname, location.search, location.state])
  const mode = settings.data?.registrationMode

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
  // Checks the code before the keys are derived (it uses nothing up).
  const checkCode = async (): Promise<boolean> => {
    const value = code.trim()
    if (!value) {
      if (mode === 'code') {
        setCodeError(t('register.codeRequired'))
        return false
      }
      return true
    }
    if (checked.current?.value !== value) {
      const entry = {
        value,
        answer: api.post('/auth/registration-code/check', { code: value }).then(
          () => null,
          (error: unknown) => {
            const problem = codeProblem(error)
            // Only the server's verdict on the code is kept; a limit or a
            // network failure is asked again next time.
            if ((!problem || problem === 'rateLimited') && checked.current === entry) checked.current = null
            return problem === 'rateLimited' ? t('register.codeRateLimited') : problem ? t('register.codeInvalid') : t('register.codeCheckFailed')
          },
        ),
      }
      checked.current = entry
    }
    const message = await checked.current.answer
    // The field may have changed while the server answered.
    if (current.current.trim() === value) setCodeError(message)
    return message === null
  }

  if (settings.data && mode === 'off') {
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
      validateLeading={async () => (await trigger()) && (await checkCode())}
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
          {mode === 'code' || codeOpen ? (
            <Field label={t('register.code')} error={codeError ?? undefined} description={mode === 'code' ? t('register.codeHint') : t('register.codeOptionalHint')} required={mode === 'code'}>
              {(field) => (
                <Input
                  {...field}
                  value={code}
                  onChange={(e) => {
                    setCode(e.target.value)
                    setCodeError(null)
                  }}
                  onBlur={() => void (code.trim() ? checkCode() : undefined)}
                  autoComplete="off"
                  autoCapitalize="characters"
                  spellCheck={false}
                  placeholder="XXXXX-XXXXX-XXXXX-XXXXX"
                />
              )}
            </Field>
          ) : (
            <button type="button" className="text-sm font-medium text-primary hover:underline" onClick={() => setCodeOpen(true)}>
              {t('register.haveCode')}
            </button>
          )}
          {settings.isError ? <Alert variant="warn">{t('register.settingsUnavailable')}</Alert> : null}
        </>
      }
      onKeysConfirmed={async (keys) => {
        try {
          await registerAndSignIn(getValues('username').trim(), keys, code.trim() || undefined)
        } catch (error) {
          // The code was taken or revoked meanwhile: say so on its field.
          const problem = codeProblem(error)
          checked.current = null
          if (problem && problem !== 'registrationClosed') setCodeError(problem === 'rateLimited' ? t('register.codeRateLimited') : t('register.codeInvalid'))
          throw error
        }
        void navigate(next, { replace: true })
      }}
    />
  )
}
