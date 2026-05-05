import { useState, useEffect } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate, Link } from 'react-router-dom'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { Loader2 } from 'lucide-react'
import zxcvbn from 'zxcvbn'
import api from '@/api/client'
import { toBase64 } from '@/crypto'
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
  FormDescription,
} from '@/components/ui/form'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'

const STRENGTH_COLORS = ['bg-red-500', 'bg-orange-500', 'bg-yellow-500', 'bg-green-500', 'bg-green-600']

const formSchema = z
  .object({
    email: z.string().email('Invalid email address'),
    username: z
      .string()
      .min(3, 'At least 3 characters')
      .max(32, 'At most 32 characters')
      .regex(/^[a-z0-9_-]+$/, 'Lowercase letters, numbers, _ and - only'),
    password: z.string().min(1, 'Password is required'),
    passwordConfirm: z.string(),
  })
  .refine((d) => d.password === d.passwordConfirm, {
    path: ['passwordConfirm'],
    message: 'Passwords do not match',
  })

type FormData = z.infer<typeof formSchema>
type Step = 'form' | 'generating' | 'mnemonic' | 'confirm' | 'submitting' | 'done'

export default function Register() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const [step, setStep] = useState<Step>('form')
  const [registrationEnabled, setRegistrationEnabled] = useState<boolean | null>(null)
  const [keys, setKeys] = useState<RegistrationKeys | null>(null)
  const [mnemonicConfirm, setMnemonicConfirm] = useState('')
  const [error, setError] = useState('')
  const [email, setEmail] = useState('')
  const [username, setUsername] = useState('')

  const form = useForm<FormData>({
    resolver: zodResolver(formSchema),
    defaultValues: { email: '', username: '', password: '', passwordConfirm: '' },
  })

  const password = form.watch('password')
  const strength = zxcvbn(password ?? '')

  useEffect(() => {
    api.get('/auth/settings')
      .then((res) => setRegistrationEnabled(res.data.registrationEnabled))
      .catch(() => setRegistrationEnabled(true))
  }, [])

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
    setEmail(data.email)
    setUsername(data.username)
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
      await api.post('/auth/register', {
        email,
        username,
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
        recoveryProof: keys.recoveryKey,
      })
      setStep('done')
    } catch (err: any) {
      setError(err.response?.data?.error ?? 'Registration failed')
      setStep('mnemonic')
    }
  }

  // Loading registration status
  if (registrationEnabled === null) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    )
  }

  if (registrationEnabled === false) {
    return (
      <div className="flex min-h-screen items-center justify-center p-4">
        <Card className="w-full max-w-sm text-center">
          <CardHeader>
            <div className="flex items-center gap-2.5 justify-center mb-2">
              <KutupLogo size={34} />
              <span className="text-3xl font-bold text-primary tracking-tight">Kutup</span>
            </div>
            <CardTitle>{t('register.disabled.title')}</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <p className="text-sm text-muted-foreground">
              {t('register.disabled.desc')}
            </p>
            <Link to="/login" className="text-primary hover:underline text-sm">{t('register.disabled.backToSignIn')}</Link>
          </CardContent>
        </Card>
      </div>
    )
  }

  if (step === 'generating' || step === 'submitting') {
    return (
      <div className="flex min-h-screen items-center justify-center p-4">
        <Card className="w-full max-w-sm">
          <CardContent className="pt-8 pb-8 flex flex-col items-center gap-3">
            <Loader2 className="h-8 w-8 animate-spin text-primary" />
            <p className="text-sm font-medium">
              {step === 'generating' ? t('register.generatingKeys') : t('register.creatingAccount')}
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
          <CardHeader>
            <CardTitle>{t('register.mnemonic.title')}</CardTitle>
          </CardHeader>
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
          <CardHeader>
            <CardTitle>{t('register.confirm.title')}</CardTitle>
          </CardHeader>
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
              <Button type="submit" className="w-full">{t('register.confirm.submit')}</Button>
            </form>
          </CardContent>
        </Card>
      </div>
    )
  }

  if (step === 'done') {
    return (
      <div className="flex min-h-screen items-center justify-center p-4">
        <Card className="w-full max-w-sm text-center">
          <CardHeader><CardTitle>{t('register.success.title')}</CardTitle></CardHeader>
          <CardContent className="space-y-4">
            <p className="text-sm text-muted-foreground">{t('register.success.desc')}</p>
            <Button className="w-full" onClick={() => navigate('/login')}>{t('register.success.signIn')}</Button>
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
          <CardTitle className="text-center">{t('register.title')}</CardTitle>
        </CardHeader>
        <CardContent>
          <Form {...form}>
            <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
              <FormField
                control={form.control}
                name="email"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>{t('auth.email')}</FormLabel>
                    <FormControl>
                      <Input type="email" autoComplete="email" {...field} />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
              <FormField
                control={form.control}
                name="username"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>{t('register.username')}</FormLabel>
                    <FormControl>
                      <Input
                        autoComplete="username"
                        placeholder={t('register.usernamePlaceholder')}
                        {...field}
                        onChange={(e) => field.onChange(e.target.value.toLowerCase())}
                      />
                    </FormControl>
                    <FormDescription>{t('register.usernameDesc')}</FormDescription>
                    <FormMessage />
                  </FormItem>
                )}
              />
              <FormField
                control={form.control}
                name="password"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>{t('auth.password')}</FormLabel>
                    <FormControl>
                      <PasswordInput autoComplete="new-password" {...field} />
                    </FormControl>
                    {password && (
                      <div className="space-y-1">
                        <Progress
                          value={(strength.score + 1) * 20}
                          className={`h-1 [&>div]:${STRENGTH_COLORS[strength.score]}`}
                        />
                        <p className="text-xs text-muted-foreground">
                          {strengthLabels[strength.score]}
                        </p>
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
                    <FormLabel>{t('register.confirmPassword')}</FormLabel>
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
                {t('register.title')}
              </Button>
            </form>
          </Form>
          <p className="mt-4 text-center text-sm text-muted-foreground">
            {t('auth.alreadyHaveAccount')}{' '}
            <Link to="/login" className="text-primary hover:underline">{t('auth.signIn')}</Link>
          </p>
        </CardContent>
      </Card>
    </div>
  )
}
