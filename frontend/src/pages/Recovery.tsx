// Account recovery via BIP39 mnemonic.
// TOTP bypass is intentional: mnemonic IS the second factor.
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate, Link } from 'react-router-dom'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { Loader2 } from 'lucide-react'
import zxcvbn from 'zxcvbn'
import api from '@/api/client'
import { KutupLogo } from '@/components/KutupLogo'
import {
  decodeMnemonic, validateMnemonic,
  decrypt, encrypt,
  deriveKeyEncryptionKey, deriveLoginKey, generateKDFSalt,
  toBase64, fromBase64,
} from '@/crypto'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
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

const schema = z
  .object({
    email: z.string().email('Invalid email address'),
    mnemonic: z
      .string()
      .refine(
        (v) => validateMnemonic(v.trim().toLowerCase()),
        'Invalid recovery phrase — check for typos',
      ),
    newPassword: z.string().min(1, 'Password is required'),
    newPasswordConfirm: z.string(),
  })
  .refine((d) => d.newPassword === d.newPasswordConfirm, {
    path: ['newPasswordConfirm'],
    message: 'Passwords do not match',
  })

type FormData = z.infer<typeof schema>

export default function Recovery() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const [step, setStep] = useState<'form' | 'deriving' | 'done'>('form')
  const [error, setError] = useState('')

  const form = useForm<FormData>({
    resolver: zodResolver(schema),
    defaultValues: { email: '', mnemonic: '', newPassword: '', newPasswordConfirm: '' },
  })

  const newPassword = form.watch('newPassword')
  const strength = zxcvbn(newPassword ?? '')
  const strengthLabels = [
    t('auth.strength.veryWeak'),
    t('auth.strength.weak'),
    t('auth.strength.fair'),
    t('auth.strength.strong'),
    t('auth.strength.veryStrong'),
  ]

  async function onSubmit(data: FormData) {
    if (strength.score < 2) {
      form.setError('newPassword', { message: t('register.passwordTooWeak') })
      return
    }
    setError('')
    setStep('deriving')
    try {
      const recoveryDataRes = await api.get(`/auth/recover/preflight?email=${encodeURIComponent(data.email)}`)
      const { encryptedRecoveryKey, recoveryKeyNonce } = recoveryDataRes.data

      const recoveryKey = decodeMnemonic(data.mnemonic.trim().toLowerCase())
      const masterKey = await decrypt(fromBase64(encryptedRecoveryKey), fromBase64(recoveryKeyNonce), recoveryKey)

      const newKdfSalt = await generateKDFSalt()
      const newLoginKeySalt = await generateKDFSalt()
      const newKeyEncKey = await deriveKeyEncryptionKey(data.newPassword, newKdfSalt)
      const newLoginKey = await deriveLoginKey(data.newPassword, newLoginKeySalt)
      const newEncMK = await encrypt(masterKey, newKeyEncKey)

      await api.post('/auth/recover', {
        email: data.email,
        newLoginKey: toBase64(newLoginKey),
        newEncryptedMasterKey: toBase64(newEncMK.ciphertext),
        newMasterKeyNonce: toBase64(newEncMK.nonce),
        newKdfSalt: toBase64(newKdfSalt),
        newLoginKeySalt: toBase64(newLoginKeySalt),
        recoveryProof: toBase64(recoveryKey),
      })
      setStep('done')
    } catch (err: any) {
      setError(err.response?.data?.error ?? err.message ?? 'Recovery failed')
      setStep('form')
    }
  }

  if (step === 'deriving') {
    return (
      <div className="flex min-h-screen items-center justify-center p-4">
        <Card className="w-full max-w-sm">
          <CardContent className="pt-8 pb-8 flex flex-col items-center gap-3">
            <Loader2 className="h-8 w-8 animate-spin text-primary" />
            <p className="text-sm font-medium">{t('recovery.recovering')}</p>
            <p className="text-xs text-muted-foreground">{t('recovery.derivingNote')}</p>
          </CardContent>
        </Card>
      </div>
    )
  }

  if (step === 'done') {
    return (
      <div className="flex min-h-screen items-center justify-center p-4">
        <Card className="w-full max-w-sm text-center">
          <CardHeader><CardTitle>{t('recovery.success.title')}</CardTitle></CardHeader>
          <CardContent className="space-y-4">
            <p className="text-sm text-muted-foreground">{t('recovery.success.desc')}</p>
            <Button className="w-full" onClick={() => navigate('/login')}>{t('recovery.success.signIn')}</Button>
          </CardContent>
        </Card>
      </div>
    )
  }

  return (
    <div className="flex min-h-screen items-center justify-center p-4">
      <Card className="w-full max-w-md">
        <CardHeader>
          <div className="flex items-center gap-2.5 justify-center mb-2">
            <KutupLogo size={34} />
            <span className="text-3xl font-bold text-primary tracking-tight">Kutup</span>
          </div>
          <CardTitle className="text-center">{t('recovery.title')}</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground mb-4">
            {t('recovery.description')}
          </p>
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
                name="mnemonic"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>{t('recovery.recoveryPhrase')}</FormLabel>
                    <FormControl>
                      <textarea
                        className="w-full min-h-[80px] rounded-md border border-input bg-background px-3 py-2 text-sm font-mono resize-y focus:outline-none focus:ring-2 focus:ring-ring"
                        placeholder={t('recovery.phrasePlaceholder')}
                        autoComplete="off"
                        {...field}
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
              <FormField
                control={form.control}
                name="newPassword"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>{t('recovery.newPassword')}</FormLabel>
                    <FormControl>
                      <Input type="password" autoComplete="new-password" {...field} />
                    </FormControl>
                    {newPassword && (
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
                name="newPasswordConfirm"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>{t('recovery.confirmNewPassword')}</FormLabel>
                    <FormControl>
                      <Input type="password" autoComplete="new-password" {...field} />
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
                {form.formState.isSubmitting && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
                {t('recovery.submit')}
              </Button>
            </form>
          </Form>
          <p className="mt-4 text-center text-sm text-muted-foreground">
            <Link to="/login" className="text-primary hover:underline">{t('recovery.backToSignIn')}</Link>
          </p>
        </CardContent>
      </Card>
    </div>
  )
}
