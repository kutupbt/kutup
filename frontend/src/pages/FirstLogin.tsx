import { useState, useEffect } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { Loader2 } from 'lucide-react'
import zxcvbn from 'zxcvbn'
import { useAppDispatch } from '@/store'
import { setAuth } from '@/store/authSlice'
import api from '@/api/client'
import type { RegistrationKeys } from '@/crypto'
import { KutupLogo } from '@/components/KutupLogo'
import MnemonicDisplay from '@/components/MnemonicDisplay'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { PasswordInput } from '@/components/ui/password-input'
import { Progress } from '@/components/ui/progress'
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

const formSchema = z
  .object({
    password: z.string().min(1, 'Password is required'),
    passwordConfirm: z.string(),
  })
  .refine((d) => d.password === d.passwordConfirm, {
    path: ['passwordConfirm'],
    message: 'Passwords do not match',
  })

type FormData = z.infer<typeof formSchema>
type Step = 'form' | 'generating' | 'mnemonic' | 'confirm' | 'submitting'

export default function FirstLogin() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const dispatch = useAppDispatch()
  const [step, setStep] = useState<Step>('form')
  const [keys, setKeys] = useState<RegistrationKeys | null>(null)
  const [mnemonicConfirm, setMnemonicConfirm] = useState('')
  const [error, setError] = useState('')

  // Snapshot once on mount: handleConfirmMnemonic clears these items in
  // sessionStorage right before navigating to /drive. If we re-read on every
  // render, the post-submit re-render of this component sees them empty and
  // fires the redirect effect below — racing the navigate('/drive') and
  // bouncing the user back to /login with a still-valid session.
  const [email] = useState(() => sessionStorage.getItem('setup_email') ?? '')
  const [setupToken] = useState(() => sessionStorage.getItem('setup_token') ?? '')

  useEffect(() => {
    if (!setupToken) navigate('/login')
  }, [setupToken, navigate])

  const form = useForm<FormData>({
    resolver: zodResolver(formSchema),
    defaultValues: { password: '', passwordConfirm: '' },
  })

  const password = form.watch('password')
  const strength = zxcvbn(password ?? '')
  const strengthLabels = [
    t('auth.strength.veryWeak'),
    t('auth.strength.weak'),
    t('auth.strength.fair'),
    t('auth.strength.strong'),
    t('auth.strength.veryStrong'),
  ]

  async function onSubmit(data: FormData) {
    if (strength.score < 2) {
      form.setError('password', { message: t('register.passwordTooWeak') })
      return
    }
    setStep('generating')
    await new Promise<void>((resolve, reject) => {
      const worker = new Worker(new URL('../workers/kdf.worker.ts', import.meta.url), { type: 'module' })
      worker.onmessage = (e) => {
        const d = e.data
        if (d.type === 'error') { worker.terminate(); reject(new Error(d.message)); return }
        if (d.type === 'register') { setKeys(d.keys); setStep('mnemonic'); worker.terminate(); resolve() }
      }
      worker.onerror = (e) => { worker.terminate(); reject(new Error(e.message)) }
      worker.postMessage({ type: 'register', password: data.password })
    }).catch((err) => {
      setError(err.message ?? 'Key generation failed')
      setStep('form')
    })
  }

  async function handleConfirmMnemonic(e: React.FormEvent) {
    e.preventDefault()
    if (!keys) return
    const normalized = mnemonicConfirm
      .trim().toLowerCase().replace(/\b\d+\.\s*/g, '').replace(/\s+/g, ' ').trim()
    if (normalized !== keys.mnemonic.trim().toLowerCase()) {
      setError('Recovery phrase does not match. Check each word carefully.')
      return
    }
    setStep('submitting')
    setError('')
    try {
      const res = await api.post(
        '/auth/complete-setup',
        {
          email,
          loginKey: keys.loginKey,
          encryptedMasterKey: keys.encryptedMasterKey,
          masterKeyNonce: keys.masterKeyNonce,
          encryptedRecoveryKey: keys.encryptedRecoveryKey,
          recoveryKeyNonce: keys.recoveryKeyNonce,
          encryptedPrivateKey: keys.encryptedPrivateKey,
          privateKeyNonce: keys.privateKeyNonce,
          publicKey: keys.publicKey,
          kdfSalt: keys.kdfSalt,
          loginKeySalt: keys.loginKeySalt,
        },
        { headers: { Authorization: `Bearer ${setupToken}` } },
      )
      sessionStorage.removeItem('setup_token')
      sessionStorage.removeItem('setup_email')
      dispatch(setAuth({
        userId: res.data.userId,
        email,
        username: res.data.username,
        accessToken: res.data.accessToken,
        masterKey: keys.masterKey,
        privateKey: keys.privateKey,
        publicKey: keys.publicKey,
        isAdmin: res.data.isAdmin,
        storageQuotaBytes: res.data.storageQuotaBytes,
        storageUsedBytes: res.data.storageUsedBytes,
        color: res.data.color ?? null,
      }))
      navigate('/drive')
    } catch (err: any) {
      setError(err.response?.data?.error ?? 'Setup failed')
      setStep('mnemonic')
    }
  }

  if (step === 'generating' || step === 'submitting') {
    return (
      <div className="flex min-h-screen items-center justify-center p-4">
        <Card className="w-full max-w-sm">
          <CardContent className="pt-8 pb-8 flex flex-col items-center gap-3">
            <Loader2 className="h-8 w-8 animate-spin text-primary" />
            <p className="text-sm font-medium">
              {step === 'generating' ? t('firstLogin.generatingKeys') : t('firstLogin.finishingSetup')}
            </p>
            {step === 'generating' && (
              <p className="text-xs text-muted-foreground">{t('auth.argon2idNote')}</p>
            )}
          </CardContent>
        </Card>
      </div>
    )
  }

  if (step === 'mnemonic' && keys) {
    return (
      <div className="flex min-h-screen items-center justify-center p-4">
        <Card className="w-full max-w-xl">
          <CardHeader><CardTitle>{t('register.mnemonic.title')}</CardTitle></CardHeader>
          <CardContent className="space-y-4">
            <Alert className="border-yellow-500/50 text-yellow-400 bg-yellow-500/10">
              <AlertDescription>
                This 24-word phrase is shown <strong>once</strong>. Write it down and store it safely.
                It is the only way to recover your account if you forget your password.
              </AlertDescription>
            </Alert>
            <MnemonicDisplay mnemonic={keys.mnemonic} />
            <Button className="w-full" onClick={() => setStep('confirm')}>
              {t('register.mnemonic.saved')}
            </Button>
          </CardContent>
        </Card>
      </div>
    )
  }

  if (step === 'confirm') {
    return (
      <div className="flex min-h-screen items-center justify-center p-4">
        <Card className="w-full max-w-xl">
          <CardHeader><CardTitle>{t('register.confirm.title')}</CardTitle></CardHeader>
          <CardContent>
            <form onSubmit={handleConfirmMnemonic} className="space-y-4">
              <p className="text-sm text-muted-foreground">{t('register.confirm.instruction')}</p>
              <textarea
                className="w-full min-h-[100px] rounded-md border border-input bg-background px-3 py-2 text-sm font-mono resize-y focus:outline-none focus:ring-2 focus:ring-ring"
                value={mnemonicConfirm}
                onChange={(e) => setMnemonicConfirm(e.target.value)}
                placeholder={t('register.confirm.placeholder')}
                autoComplete="off"
                required
              />
              {error && (
                <Alert variant="destructive">
                  <AlertDescription>{error}</AlertDescription>
                </Alert>
              )}
              <Button type="submit" className="w-full">{t('firstLogin.completeSetup')}</Button>
            </form>
          </CardContent>
        </Card>
      </div>
    )
  }

  return (
    <div className="flex min-h-screen items-center justify-center p-4">
      <Card className="w-full max-w-sm">
        <CardHeader>
          <div className="flex items-center gap-2.5 justify-center mb-2">
            <KutupLogo size={34} />
            <span className="text-3xl font-bold text-primary tracking-tight">Kutup</span>
          </div>
          <CardTitle className="text-center">{t('firstLogin.title')}</CardTitle>
        </CardHeader>
        <CardContent>
          {email && (
            <p className="text-sm text-muted-foreground mb-4">
              {t('firstLogin.welcomeDesc')}{' '}
              <span className="text-primary">{email}</span>
            </p>
          )}
          <Form {...form}>
            <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
              <FormField
                control={form.control}
                name="password"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>{t('firstLogin.newPassword')}</FormLabel>
                    <FormControl>
                      <PasswordInput autoComplete="new-password" autoFocus {...field} />
                    </FormControl>
                    {password && (
                      <div className="space-y-1">
                        <Progress value={(strength.score + 1) * 20} className="h-1" />
                        <p className="text-xs text-muted-foreground">{strengthLabels[strength.score]}</p>
                      </div>
                    )}
                    <FormMessage />
                  </FormItem>
                )}
              />
              <FormField
                control={form.control}
                name="passwordConfirm"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>{t('firstLogin.confirmPassword')}</FormLabel>
                    <FormControl>
                      <PasswordInput autoComplete="new-password" {...field} />
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
              <Button type="submit" className="w-full" disabled={form.formState.isSubmitting}>
                {t('firstLogin.continue')}
              </Button>
            </form>
          </Form>
        </CardContent>
      </Card>
    </div>
  )
}
