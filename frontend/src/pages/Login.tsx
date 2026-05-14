import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate, useSearchParams, Link } from 'react-router-dom'
import { toast } from 'sonner'
import { sanitizeNext } from '@/lib/sessionSync'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { Loader2 } from 'lucide-react'
import { useAppDispatch } from '@/store'
import { setAuth } from '@/store/authSlice'
import { store } from '@/store'
import api from '@/api/client'
import { decryptMasterKey, decryptPrivateKey, toBase64 } from '@/crypto'
import { isTauri } from '@/lib/isTauri'
import {
  getServerUrl,
  clearServerUrl,
} from '@/lib/serverConfig'
import { invalidateApiBase } from '@/lib/apiBase'
import * as sessionVault from '@/lib/sessionVault'
import { KutupLogo } from '@/components/KutupLogo'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { PasswordInput } from '@/components/ui/password-input'
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from '@/components/ui/form'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'

type Step = 'credentials' | 'deriving' | 'totp' | 'decrypting'

const credSchema = z.object({
  email: z.string().email('Invalid email address'),
  password: z.string().min(1, 'Password is required'),
})
const totpSchema = z.object({
  code: z.string().length(6, 'Code must be 6 digits').regex(/^\d+$/, 'Digits only'),
})

type CredForm = z.infer<typeof credSchema>
type TotpForm = z.infer<typeof totpSchema>

function deriveInWorker(
  password: string,
  kdfSalt: string,
  loginKeySalt: string,
): Promise<{ keyEncryptionKey: Uint8Array; loginKey: Uint8Array }> {
  return new Promise((resolve, reject) => {
    const worker = new Worker(new URL('../workers/kdf.worker.ts', import.meta.url), { type: 'module' })
    worker.onmessage = (e) => {
      worker.terminate()
      if (e.data.type === 'error') reject(new Error(e.data.message))
      else
        resolve({
          keyEncryptionKey: new Uint8Array(Object.values(e.data.keyEncryptionKey)),
          loginKey: new Uint8Array(Object.values(e.data.loginKey)),
        })
    }
    worker.onerror = (e) => { worker.terminate(); reject(e) }
    worker.postMessage({ type: 'deriveKeys', password, kdfSalt, loginKeySalt })
  })
}

export default function Login() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()
  const nextParam = sanitizeNext(searchParams.get('next')) ?? '/drive'
  const dispatch = useAppDispatch()
  const [step, setStep] = useState<Step>('credentials')
  const [error, setError] = useState('')
  const [preAuthToken, setPreAuthToken] = useState('')
  const [savedEmail, setSavedEmail] = useState('')
  const [savedPassword, setSavedPassword] = useState('')

  const credForm = useForm<CredForm>({ resolver: zodResolver(credSchema) })
  const totpForm = useForm<TotpForm>({ resolver: zodResolver(totpSchema) })

  // Tauri-only: if no server URL has been picked yet, bounce to the server-
  // select page. Web (`!isTauri`) is always same-origin so this is a no-op.
  useEffect(() => {
    if (!isTauri) return
    let cancelled = false
    ;(async () => {
      const url = await getServerUrl()
      if (!cancelled && !url) navigate('/server-select', { replace: true })
    })()
    return () => {
      cancelled = true
    }
  }, [navigate])

  async function onSwitchServer() {
    await clearServerUrl()
    invalidateApiBase()
    navigate('/server-select', { replace: true })
  }

  async function onCredSubmit({ email, password }: CredForm) {
    setError('')
    setStep('deriving')
    try {
      const preflightRes = await api.get(`/auth/login/preflight?email=${encodeURIComponent(email)}`)
      const { kdfSalt, loginKeySalt } = preflightRes.data

      let loginKeyB64: string
      let keyEncryptionKey: Uint8Array | null = null

      if (kdfSalt === '') {
        loginKeyB64 = toBase64(new TextEncoder().encode(password))
      } else {
        const derived = await deriveInWorker(password, kdfSalt, loginKeySalt)
        keyEncryptionKey = derived.keyEncryptionKey
        loginKeyB64 = toBase64(derived.loginKey)
      }

      const loginRes = await api.post('/auth/login', { email, loginKey: loginKeyB64 })

      if (loginRes.data.requiresSetup) {
        sessionStorage.setItem('setup_token', loginRes.data.setupToken)
        sessionStorage.setItem('setup_email', email)
        navigate('/first-login')
        return
      }

      if (loginRes.data.requiresTotp) {
        setSavedEmail(email)
        setSavedPassword(password)
        setPreAuthToken(loginRes.data.preAuthToken)
        setStep('totp')
        return
      }

      await finalizeLogin(loginRes.data, keyEncryptionKey!)
    } catch (err: any) {
      setError(err.response?.data?.error ?? 'Login failed')
      setStep('credentials')
    }
  }

  async function onTotpSubmit({ code }: TotpForm) {
    setError('')
    setStep('decrypting')
    try {
      const preflightRes = await api.get(`/auth/login/preflight?email=${encodeURIComponent(savedEmail)}`)
      const { kdfSalt, loginKeySalt } = preflightRes.data
      const { keyEncryptionKey } = await deriveInWorker(savedPassword, kdfSalt, loginKeySalt)

      const res = await api.post('/auth/login/2fa', { preAuthToken, code })
      await finalizeLogin(res.data, keyEncryptionKey)
    } catch (err: any) {
      setError(err.response?.data?.error ?? 'Invalid code')
      setStep('totp')
    }
  }

  async function finalizeLogin(data: any, keyEncryptionKey: Uint8Array) {
    setStep('decrypting')
    const masterKey = await decryptMasterKey(data.encryptedMasterKey, data.masterKeyNonce, keyEncryptionKey)
    const privateKey = await decryptPrivateKey(data.encryptedPrivateKey, data.privateKeyNonce, masterKey)
    dispatch(setAuth({
      userId: data.userId,
      email: savedEmail || credForm.getValues('email'),
      username: data.username,
      accessToken: data.accessToken,
      masterKey,
      privateKey,
      publicKey: data.publicKey,
      isAdmin: data.isAdmin,
      storageQuotaBytes: data.storageQuotaBytes,
      storageUsedBytes: data.storageUsedBytes,
      color: data.color ?? null,
    }))

    // Persist to the OS keychain so the next launch silently restores the
    // session (Nextcloud / Signal / Element model). Tauri-only — web stays
    // on the sessionStorage path. Failures here just mean "stay signed in"
    // is unavailable on this device (e.g. headless Linux with no Secret
    // Service daemon); the user is still signed in for this run, so we
    // surface a toast and move on.
    if (isTauri) {
      try {
        const s = store.getState().auth
        await sessionVault.save({
          profile: {
            userId: s.userId!,
            email: s.email!,
            username: s.username,
            isAdmin: s.isAdmin,
            storageQuotaBytes: s.storageQuotaBytes,
            storageUsedBytes: s.storageUsedBytes,
            totpEnabled: s.totpEnabled,
            color: s.color,
            currentDeviceId: s.currentDeviceId,
            publicKey: s.publicKey!,
          },
          secrets: {
            accessToken: s.accessToken!,
            masterKey,
            privateKey,
          },
        })
      } catch (e) {
        if (e instanceof sessionVault.VaultUnavailableError) {
          toast.warning(t('auth.vaultUnavailable'))
        }
      }
    }

    navigate(nextParam)
  }

  const isBusy = step === 'deriving' || step === 'decrypting'

  if (isBusy) {
    return (
      <div className="flex min-h-screen items-center justify-center px-4 pt-[max(1rem,env(safe-area-inset-top))] pb-[max(1rem,env(safe-area-inset-bottom))]">
        <Card className="w-full max-w-sm">
          <CardContent className="pt-8 pb-8 flex flex-col items-center gap-3">
            <Loader2 className="h-8 w-8 animate-spin text-primary" />
            <p className="text-sm font-medium">
              {step === 'deriving' ? t('auth.derivingKeys') : t('auth.decryptingVault')}
            </p>
            <p className="text-xs text-muted-foreground text-center">
              {step === 'deriving'
                ? t('auth.argon2idNote')
                : t('auth.decryptingLocally')}
            </p>
          </CardContent>
        </Card>
      </div>
    )
  }

  if (step === 'totp') {
    return (
      <div className="flex min-h-screen items-center justify-center px-4 pt-[max(1rem,env(safe-area-inset-top))] pb-[max(1rem,env(safe-area-inset-bottom))]">
        <Card className="w-full max-w-sm">
          <CardHeader>
            <CardTitle>{t('auth.totp.title')}</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-sm text-muted-foreground mb-4">
              {t('auth.totp.enterCode')}
            </p>
            <Form {...totpForm}>
              <form onSubmit={totpForm.handleSubmit(onTotpSubmit)} className="space-y-4">
                <FormField
                  control={totpForm.control}
                  name="code"
                  render={({ field }) => (
                    <FormItem>
                      <FormControl>
                        <Input
                          type="text"
                          inputMode="numeric"
                          pattern="[0-9]{6}"
                          maxLength={6}
                          className="text-center text-2xl tracking-widest"
                          placeholder="000000"
                          autoFocus
                          autoComplete="one-time-code"
                          {...field}
                        />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                {error && (
                  <Alert variant="destructive">
                    <AlertDescription>{error}</AlertDescription>
                  </Alert>
                )}
                <Button type="submit" className="w-full" disabled={totpForm.formState.isSubmitting}>
                  {totpForm.formState.isSubmitting && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
                  {t('auth.totp.verify')}
                </Button>
              </form>
            </Form>
          </CardContent>
        </Card>
      </div>
    )
  }

  return (
    <div className="flex min-h-screen items-center justify-center px-4 pt-[max(1rem,env(safe-area-inset-top))] pb-[max(1rem,env(safe-area-inset-bottom))]">
      <Card className="w-full max-w-sm">
        <CardHeader>
          <div className="flex items-center gap-2.5 justify-center mb-2">
            <KutupLogo size={34} />
            <span className="text-3xl font-bold text-primary tracking-tight">Kutup</span>
          </div>
          <CardTitle className="text-center">{t('auth.signIn')}</CardTitle>
        </CardHeader>
        <CardContent>
          <Form {...credForm}>
            <form onSubmit={credForm.handleSubmit(onCredSubmit)} className="space-y-4">
              <FormField
                control={credForm.control}
                name="email"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>{t('auth.email')}</FormLabel>
                    <FormControl>
                      <Input type="email" autoComplete="email" autoFocus {...field} />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
              <FormField
                control={credForm.control}
                name="password"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>{t('auth.password')}</FormLabel>
                    <FormControl>
                      <PasswordInput autoComplete="current-password" {...field} />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
              {error && (
                <Alert variant="destructive">
                  <AlertDescription>{error}</AlertDescription>
                </Alert>
              )}
              <Button type="submit" className="w-full" disabled={credForm.formState.isSubmitting}>
                {credForm.formState.isSubmitting && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
                {t('auth.signIn')}
              </Button>
            </form>
          </Form>
          <div className="mt-4 space-y-1 text-center text-sm text-muted-foreground">
            <p>
              <Link to="/recover" className="text-primary hover:underline">{t('auth.forgotPassword')}</Link>
            </p>
            <p>
              {t('auth.noAccount')}{' '}
              <Link to="/register" className="text-primary hover:underline">{t('auth.createOne')}</Link>
            </p>
            {isTauri && (
              <p className="pt-2">
                <button
                  type="button"
                  onClick={onSwitchServer}
                  className="text-primary hover:underline"
                >
                  {t('auth.serverSelect.switchServer')}
                </button>
              </p>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
