import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { QRCodeSVG } from 'qrcode.react'
import { toast } from 'sonner'
import { Loader2, Copy } from 'lucide-react'
import { MobileAccountSubPage } from '@/pages/mobile/account/MobileAccountSubPage'
import { Surface } from '@/components/ui/surface'
import { Button } from '@/components/ui/button'
import { useAppDispatch } from '@/store'
import { updateTotpEnabled } from '@/store/authSlice'
import api from '@/api/client'
import { copyText } from '@/lib/format'

/**
 * MobileTotpSetupPage — `/drive/account/security/totp-setup`.
 *
 * Dedicated full page for the TOTP setup flow. **Not** a bottom sheet —
 * setup requires the user to switch to their authenticator app, scan the
 * QR (or paste the secret), come back, and type a 6-digit code. A sheet
 * gets dismissed on accidental swipes / background-foreground cycles,
 * which would lose the QR + secret state. A durable URL persists.
 *
 * Flow:
 *   1. On mount, POST /user/2fa/setup → returns { secret, qrUri }.
 *   2. Show QR + secret + 6-digit verify input.
 *   3. On verify success, POST /user/2fa/verify with the code →
 *      dispatch(updateTotpEnabled(true)) → toast → navigate back to
 *      /drive/account/security.
 *   4. Back button at any point exits without committing — the server
 *      keeps the unverified setup pending (idempotent), so a re-entry
 *      starts a fresh setup.
 */

const totpVerifySchema = z.object({
  code: z.string().regex(/^\d{6}$/, 'Enter the 6-digit code'),
})
type TotpVerifyForm = z.infer<typeof totpVerifySchema>

export default function MobileTotpSetupPage() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const dispatch = useAppDispatch()

  const [setup, setSetup] = useState<{ secret: string; qrUri: string } | null>(null)
  const [loadError, setLoadError] = useState<string | null>(null)
  const [secretCopied, setSecretCopied] = useState(false)
  const form = useForm<TotpVerifyForm>({ resolver: zodResolver(totpVerifySchema) })

  useEffect(() => {
    let cancelled = false
    void (async () => {
      try {
        const res = await api.post('/user/2fa/setup')
        if (!cancelled) setSetup(res.data)
      } catch (err: unknown) {
        const msg =
          (err as { response?: { data?: { error?: string } } }).response?.data?.error ??
          'Failed to start TOTP setup'
        if (!cancelled) setLoadError(msg)
      }
    })()
    return () => {
      cancelled = true
    }
  }, [])

  async function onVerify({ code }: TotpVerifyForm) {
    try {
      await api.post('/user/2fa/verify', { code })
      dispatch(updateTotpEnabled(true))
      toast.success(t('settings.totp.enabledToast'))
      navigate('/drive/account/security', { replace: true })
    } catch (err: unknown) {
      const msg =
        (err as { response?: { data?: { error?: string } } }).response?.data?.error ??
        'Invalid code'
      form.setError('code', { message: msg })
    }
  }

  async function onCopySecret() {
    if (!setup) return
    try {
      await copyText(setup.secret)
      setSecretCopied(true)
      setTimeout(() => setSecretCopied(false), 1500)
    } catch {
      // copyText already swallows the rare failure; nothing to surface.
    }
  }

  return (
    <MobileAccountSubPage title={t('settings.totp.setupTitle', 'Set up TOTP')}>
      {loadError ? (
        <Surface className="p-4 text-center">
          <p className="text-sm text-destructive font-medium">{loadError}</p>
          <Button
            className="mt-3 min-h-tap"
            onClick={() => navigate('/drive/account/security')}
          >
            {t('common.back')}
          </Button>
        </Surface>
      ) : !setup ? (
        <div className="flex flex-col items-center justify-center py-10 gap-3 text-text-tertiary">
          <Loader2 className="h-6 w-6 animate-spin" />
          <p className="text-sm">{t('common.loading')}</p>
        </div>
      ) : (
        <>
          {/* Instructions */}
          <p className="text-[13px] text-text-secondary leading-relaxed mb-4 px-1">
            {t(
              'mobile.totp.setupInstructions',
              'Open your authenticator app (Google Authenticator, 1Password, Authy, etc.) and add an account by scanning the QR code below — or pasting the key manually. Then enter the 6-digit code it generates.',
            )}
          </p>

          {/* QR */}
          <Surface className="p-5 flex justify-center mb-3">
            <div className="p-3 bg-white rounded-[var(--radius-lg)] shadow-sm">
              <QRCodeSVG value={setup.qrUri} size={220} />
            </div>
          </Surface>

          {/* Manual-entry secret */}
          <div className="mb-5">
            <div className="text-[11.5px] font-semibold tracking-[0.06em] uppercase text-text-tertiary px-1 mb-2">
              {t('settings.totp.secret', 'Or enter the key manually')}
            </div>
            <Surface className="flex items-center gap-2 px-3 py-2.5">
              <code className="flex-1 text-[13px] font-mono break-all select-all text-text-primary">
                {setup.secret}
              </code>
              <button
                type="button"
                onClick={onCopySecret}
                aria-label={t('mobile.totp.copySecret', 'Copy secret')}
                className="shrink-0 px-2.5 py-1.5 text-[12px] font-medium rounded-[10px] bg-surface-sunken text-text-secondary cursor-pointer inline-flex items-center gap-1.5 hover:bg-border-light transition-colors min-h-tap"
              >
                <Copy className="h-3.5 w-3.5" />
                {secretCopied
                  ? t('common.copied', 'Copied!')
                  : t('mobile.totp.copy', 'Copy')}
              </button>
            </Surface>
          </div>

          {/* Verify */}
          <div className="mb-3">
            <div className="text-[11.5px] font-semibold tracking-[0.06em] uppercase text-text-tertiary px-1 mb-2">
              {t('mobile.totp.enterCodeLabel', 'Enter the 6-digit code')}
            </div>
            <form onSubmit={form.handleSubmit(onVerify)} className="flex flex-col gap-3">
              <input
                type="text"
                inputMode="numeric"
                pattern="[0-9]{6}"
                maxLength={6}
                autoComplete="one-time-code"
                autoFocus
                placeholder="000000"
                className="w-full h-14 text-center text-[28px] tracking-[0.5em] font-mono rounded-[var(--radius-lg)] border border-border bg-surface text-text-primary focus:outline-none focus:ring-2 focus:ring-primary"
                {...form.register('code')}
              />
              {form.formState.errors.code && (
                <p className="text-[12px] text-destructive text-center" role="alert">
                  {form.formState.errors.code.message}
                </p>
              )}
              <Button
                type="submit"
                className="w-full min-h-tap"
                disabled={form.formState.isSubmitting}
              >
                {form.formState.isSubmitting && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
                {t('settings.totp.verify', 'Verify and enable')}
              </Button>
            </form>
          </div>

          <p className="text-[11.5px] text-text-tertiary px-1">
            {t(
              'mobile.totp.lossNote',
              'If you lose access to your authenticator app, use your 24-word recovery phrase to restore the account.',
            )}
          </p>
        </>
      )}
    </MobileAccountSubPage>
  )
}
