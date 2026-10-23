import { useEffect, useRef, useState } from 'react'
import { Copy, Loader2, RefreshCw } from 'lucide-react'
import { QRCodeSVG } from 'qrcode.react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { openProvisioning } from '@kutup/chat-core/provisioning'
import type { WasmLinkingDeviceHandle } from '@kutup/chat-core/types'
import { loadChatWasm } from '@kutup/chat-core/wasm'
import type { Session } from '@kutup/session/store'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { ConfirmDestructive } from '@kutup/ui/components/confirm-destructive'
import { Mono } from '@kutup/ui/components/mono'
import { copyText } from '@kutup/ui/lib/clipboard'
import { openChatWith } from './chatStore'

type Step =
  | { kind: 'starting' }
  | { kind: 'code'; code: string }
  | { kind: 'expired' }
  | { kind: 'failed' }

/**
 * "Link this device" (docs/plans/account-identity-key.md): another device of
 * the account holds its Chat identity, so this browser shows a code — a QR
 * code, and the same as text for a device without a camera — and waits for
 * that device to send it the identity. Behind it, for someone with none of
 * their other devices: start over, which drops them.
 */
export function LinkThisDevice({ session }: { session: Session }) {
  const { t } = useTranslation()
  const [step, setStep] = useState<Step>({ kind: 'starting' })
  const [attempt, setAttempt] = useState(0)
  const [startOver, setStartOver] = useState(false)
  const linkingRef = useRef<WasmLinkingDeviceHandle | null>(null)

  useEffect(() => {
    let closed = false
    let close: (() => void) | null = null
    setStep({ kind: 'starting' })
    void (async () => {
      try {
        const wasm = await loadChatWasm()
        if (closed) return
        const linking = new wasm.WasmLinkingDevice()
        linkingRef.current = linking
        close = await openProvisioning(linking, {
          onCode: (code) => !closed && setStep({ kind: 'code', code }),
          onEnvelope: (envelope) => {
            if (closed) return
            closed = true
            // The chat opens with the identity the other device sent; the
            // gate shows its progress and any failure from here.
            openChatWith(session, { kind: 'link', linking, envelope })
          },
          onExpired: () => !closed && setStep({ kind: 'expired' }),
          onError: (error) => {
            console.warn('chat: linking failed', error)
            if (!closed) setStep({ kind: 'failed' })
          },
        })
        if (closed) close()
      } catch (error) {
        console.warn('chat: could not start linking', error)
        if (!closed) setStep({ kind: 'failed' })
      }
    })()
    return () => {
      closed = true
      close?.()
    }
  }, [session, attempt])

  return (
    <div className="mx-auto flex min-h-svh max-w-md flex-col justify-center gap-5 p-6" data-testid="chat-link-this-device">
      <div className="grid gap-2">
        <h1 className="text-xl font-semibold">{t('chat.link.title')}</h1>
        <p className="text-sm text-muted-foreground">{t('chat.link.body')}</p>
      </div>

      {step.kind === 'starting' ? (
        <p className="flex items-center gap-2 text-sm text-muted-foreground" role="status">
          <Loader2 className="size-4 animate-spin" aria-hidden />
          {t('chat.link.starting')}
        </p>
      ) : null}

      {step.kind === 'code' ? (
        <div className="grid gap-4">
          <ol className="list-decimal space-y-1 ps-5 text-sm">
            <li>{t('chat.link.stepOpen')}</li>
            <li>{t('chat.link.stepSettings')}</li>
            <li>{t('chat.link.stepScan')}</li>
          </ol>
          <div className="flex justify-center">
            <div className="rounded-xl bg-white p-4" data-testid="chat-link-qr" data-value={step.code}>
              <QRCodeSVG value={step.code} size={220} level="M" title={t('chat.link.qrLabel')} />
            </div>
          </div>
          <div className="grid gap-2">
            <div className="flex items-center justify-between gap-2">
              <span className="text-xs font-medium">{t('chat.link.codeLabel')}</span>
              <Button
                type="button"
                size="sm"
                variant="ghost"
                data-testid="chat-link-copy"
                onClick={() =>
                  void copyText(step.code).then(
                    () => toast.success(t('chat.link.copied')),
                    () => toast.error(t('chat.link.copyFailed')),
                  )
                }
              >
                <Copy />
                {t('common.copy')}
              </Button>
            </div>
            <Mono as="code" className="break-all rounded-lg bg-muted p-3 text-xs" data-testid="chat-link-code">
              {step.code}
            </Mono>
            <Alert variant="warn">{t('chat.link.codeAdvice')}</Alert>
          </div>
          <p className="flex items-center gap-2 text-sm text-muted-foreground" role="status">
            <Loader2 className="size-4 animate-spin" aria-hidden />
            {t('chat.link.waiting')}
          </p>
        </div>
      ) : null}

      {step.kind === 'expired' || step.kind === 'failed' ? (
        <div className="grid gap-3">
          <Alert variant={step.kind === 'failed' ? 'error' : 'warn'}>
            {step.kind === 'expired' ? t('chat.link.expired') : t('chat.link.failed')}
          </Alert>
          <Button onClick={() => setAttempt((value) => value + 1)} data-testid="chat-link-new-code">
            <RefreshCw />
            {t('chat.link.newCode')}
          </Button>
        </div>
      ) : null}

      <div className="border-t pt-4">
        <Button variant="link" className="h-auto px-0" onClick={() => setStartOver(true)} data-testid="chat-link-no-devices">
          {t('chat.link.noDevices')}
        </Button>
      </div>

      <ConfirmDestructive
        open={startOver}
        onOpenChange={setStartOver}
        title={t('chat.link.startOverTitle')}
        description={t('chat.link.startOverDescription')}
        warning={t('chat.link.startOverWarning')}
        submit={t('chat.link.startOverConfirm')}
        errorFallback={t('chat.errors.unavailable')}
        onConfirm={() => {
          linkingRef.current?.free()
          linkingRef.current = null
          openChatWith(session, { kind: 'reregister' })
        }}
      />
    </div>
  )
}
