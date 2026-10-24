import { QRCodeSVG } from 'qrcode.react'
import { useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { useRequiredSession } from '@kutup/session/store'
import { Alert } from '@kutup/ui/components/alert'
import { Badge } from '@kutup/ui/components/badge'
import { Button } from '@kutup/ui/components/button'
import { Card, CardContent } from '@kutup/ui/components/card'
import { Field } from '@kutup/ui/components/field'
import { Input } from '@kutup/ui/components/input'
import { Mono } from '@kutup/ui/components/mono'
import { PageBody, PageHeader, Section } from '@kutup/ui/components/page'
import { OneUseSecret, ReauthLockedError, WrongPasswordError } from '@kutup/session/reauth'
import { PasswordInput } from '@kutup/ui/components/password-input'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { DataStateSection } from './DataStateSection'
import {
  useDisableTotp,
  useRecoveryCodesLeft,
  useRenewRecoveryCodes,
  useStartTotp,
  useVerifyTotp,
  type TotpEnrolment,
} from './api'
import { ChangePasswordSection } from './ChangePasswordSection'
import { SecurityEventsSection } from './SecurityEventsSection'

function CodeField({
  label,
  value,
  onChange,
  recovery = false,
}: {
  label: string
  value: string
  onChange: (value: string) => void
  /** Takes a recovery code as well as an authenticator code. */
  recovery?: boolean
}) {
  return (
    <Field label={label} required>
      {(field) => (
        <Input
          {...field}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          autoComplete="one-time-code"
          inputMode={recovery ? 'text' : 'numeric'}
          maxLength={recovery ? 13 : 6}
          spellCheck={false}
          className="max-w-48 font-mono tracking-widest"
        />
      )}
    </Field>
  )
}

/** New recovery codes, shown once: copied, downloaded, then put away. */
function RecoveryCodesShown({ codes, onDone }: { codes: string[]; onDone: () => void }) {
  const { t } = useTranslation()
  const session = useRequiredSession()
  const text = `${t('settings.security.codesFileHeader', { account: session.username })}\n\n${codes.join('\n')}\n`

  function download() {
    const url = URL.createObjectURL(new Blob([text], { type: 'text/plain' }))
    const a = document.createElement('a')
    a.href = url
    a.download = 'kutup-recovery-codes.txt'
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="space-y-4">
      <Alert variant="warn" title={t('settings.security.saveCodesTitle')}>
        {t('settings.security.saveCodesNote')}
      </Alert>
      <ol className="grid grid-cols-2 gap-x-6 gap-y-1.5 rounded-md border border-border bg-muted/40 p-4">
        {codes.map((code) => (
          <li key={code} className="font-mono text-sm">
            {code}
          </li>
        ))}
      </ol>
      <div className="flex flex-wrap gap-2">
        <Button
          type="button"
          variant="outline"
          onClick={() => {
            void navigator.clipboard.writeText(text).then(() => toast.success(t('settings.security.codesCopied')))
          }}
        >
          {t('settings.security.copyCodes')}
        </Button>
        <Button type="button" variant="outline" onClick={download}>
          {t('settings.security.downloadCodes')}
        </Button>
        <Button type="button" onClick={onDone}>
          {t('settings.security.codesSaved')}
        </Button>
      </div>
    </div>
  )
}

/** How many recovery codes are left, and new ones in their place. */
function RecoveryCodes({ onCodes }: { onCodes: (codes: string[]) => void }) {
  const { t } = useTranslation()
  const left = useRecoveryCodesLeft(true)
  const renew = useRenewRecoveryCodes()
  const [open, setOpen] = useState(false)
  const [password, setPassword] = useState('')

  return (
    <div className="space-y-3">
      <p className="text-sm">
        {left.data === undefined
          ? null
          : left.data === 0
            ? t('settings.security.codesNone')
            : t('settings.security.codesLeft', { count: left.data })}
      </p>
      {open ? (
        <form
          className="space-y-4"
          onSubmit={(event) => {
            event.preventDefault()
            renew.mutate(new OneUseSecret(password), {
              onSuccess: (codes) => {
                setOpen(false)
                onCodes(codes)
              },
            })
            setPassword('')
          }}
        >
          <Alert variant="warn">{t('settings.security.renewWarning')}</Alert>
          <PasswordField value={password} onChange={setPassword} />
          {renew.isError ? (
            <Alert variant="error">{totpFailure(renew.error, t, 'settings.security.renewFailed')}</Alert>
          ) : null}
          <div className="flex gap-2">
            <Button type="button" variant="outline" onClick={() => setOpen(false)}>
              {t('common.cancel')}
            </Button>
            <Button type="submit" loading={renew.isPending}>
              {t('settings.security.renewCodes')}
            </Button>
          </div>
        </form>
      ) : (
        <Button variant="outline" onClick={() => setOpen(true)}>
          {t('settings.security.renewCodes')}
        </Button>
      )}
    </div>
  )
}

/** The account password, which a change to the second factor needs (a `totp` grant). */
function PasswordField({ value, onChange }: { value: string; onChange: (value: string) => void }) {
  const { t } = useTranslation()
  return (
    <Field label={t('settings.security.yourPassword')} required>
      {(field) => (
        <PasswordInput {...field} value={value} onChange={(e) => onChange(e.target.value)} autoComplete="current-password" />
      )}
    </Field>
  )
}

/** What went wrong with a change to the second factor, in the person's language. */
function totpFailure(error: unknown, t: ReturnType<typeof useTranslation>['t'], fallbackKey: string): string {
  if (error instanceof WrongPasswordError) return t('settings.security.wrongPassword')
  if (error instanceof ReauthLockedError) return t(error.reason === 'rateLimited' ? 'auth.errors.slowDown' : 'auth.errors.locked')
  return apiErrorMessage(error, t(fallbackKey))
}

function Enrol({ onCodes }: { onCodes: (codes: string[]) => void }) {
  const { t } = useTranslation()
  const start = useStartTotp()
  const verify = useVerifyTotp()
  const [enrolment, setEnrolment] = useState<TotpEnrolment | null>(null)
  const [code, setCode] = useState('')
  const [password, setPassword] = useState('')

  if (!enrolment) {
    return (
      <div className="space-y-3">
        {start.isError ? (
          <Alert variant="error">{apiErrorMessage(start.error, t('settings.security.startFailed'))}</Alert>
        ) : null}
        <Button
          loading={start.isPending}
          onClick={() => start.mutate(undefined, { onSuccess: setEnrolment })}
        >
          {t('settings.security.enable')}
        </Button>
      </div>
    )
  }

  function submit(event: FormEvent) {
    event.preventDefault()
    verify.mutate(
      { code: code.trim(), password: new OneUseSecret(password) },
      {
        onSuccess: (codes) => {
          toast.success(t('settings.security.enabled'))
          setEnrolment(null)
          setCode('')
          onCodes(codes)
        },
      },
    )
    // Asked again for each try; the grant it buys is made at the last moment.
    setPassword('')
  }

  return (
    <form className="space-y-4" onSubmit={submit}>
      <ol className="list-decimal space-y-4 pl-5 text-sm">
        <li>
          <p>{t('settings.security.scan')}</p>
          <div className="mt-3 inline-block rounded-md bg-card p-3 ring-1 ring-border">
            {/* QR codes need dark-on-light to scan; this stays white in both themes. */}
            <QRCodeSVG value={enrolment.qrUri} size={176} bgColor="#ffffff" fgColor="#000000" />
          </div>
          <p className="mt-2 text-muted-foreground">
            {t('settings.security.manual')} <Mono className="break-all">{enrolment.secret}</Mono>
          </p>
        </li>
        <li>
          <CodeField label={t('settings.security.code')} value={code} onChange={setCode} />
        </li>
        <li>
          <PasswordField value={password} onChange={setPassword} />
        </li>
      </ol>
      {verify.isError ? (
        <Alert variant="error">{totpFailure(verify.error, t, 'settings.security.verifyFailed')}</Alert>
      ) : null}
      <div className="flex gap-2">
        <Button type="button" variant="outline" onClick={() => setEnrolment(null)}>
          {t('common.cancel')}
        </Button>
        <Button type="submit" loading={verify.isPending}>
          {t('settings.security.verify')}
        </Button>
      </div>
    </form>
  )
}

function Disable() {
  const { t } = useTranslation()
  const disable = useDisableTotp()
  const [open, setOpen] = useState(false)
  const [code, setCode] = useState('')
  const [password, setPassword] = useState('')

  if (!open) {
    return (
      <Button variant="outline" onClick={() => setOpen(true)}>
        {t('settings.security.disable')}
      </Button>
    )
  }
  return (
    <form
      className="space-y-4"
      onSubmit={(event) => {
        event.preventDefault()
        disable.mutate(
          { code: code.trim(), password: new OneUseSecret(password) },
          {
            onSuccess: () => {
              toast.success(t('settings.security.disabled'))
              setOpen(false)
              setCode('')
            },
          },
        )
        setPassword('')
      }}
    >
      <Alert variant="warn">{t('settings.security.disableWarning')}</Alert>
      <CodeField label={t('settings.security.codeOrRecovery')} value={code} onChange={setCode} recovery />
      <PasswordField value={password} onChange={setPassword} />
      {disable.isError ? (
        <Alert variant="error">{totpFailure(disable.error, t, 'settings.security.disableFailed')}</Alert>
      ) : null}
      <div className="flex gap-2">
        <Button type="button" variant="outline" onClick={() => setOpen(false)}>
          {t('common.cancel')}
        </Button>
        <Button type="submit" variant="destructive" loading={disable.isPending}>
          {t('settings.security.disable')}
        </Button>
      </div>
    </form>
  )
}

export function SecurityPage() {
  const { t } = useTranslation()
  const session = useRequiredSession()
  // Recovery codes just made, shown until put away.
  const [shownCodes, setShownCodes] = useState<string[] | null>(null)

  return (
    <PageBody width="prose">
      <PageHeader title={t('settings.security.title')} description={t('settings.security.description')} />

      <Section
        title={t('settings.security.twoFactor')}
        description={t('settings.security.twoFactorDescription')}
        actions={
          session.totpEnabled ? (
            <Badge variant="ok">{t('settings.security.on')}</Badge>
          ) : (
            <Badge variant="neutral">{t('settings.security.off')}</Badge>
          )
        }
      >
        <Card>
          <CardContent className="p-5">
            {shownCodes ? (
              <RecoveryCodesShown codes={shownCodes} onDone={() => setShownCodes(null)} />
            ) : session.totpEnabled ? (
              <Disable />
            ) : (
              <Enrol onCodes={setShownCodes} />
            )}
          </CardContent>
        </Card>
      </Section>

      {session.totpEnabled && !shownCodes ? (
        <Section title={t('settings.security.recoveryCodes')} description={t('settings.security.recoveryCodesDescription')}>
          <Card>
            <CardContent className="p-5">
              <RecoveryCodes onCodes={setShownCodes} />
            </CardContent>
          </Card>
        </Section>
      ) : null}

      <ChangePasswordSection />

      <SecurityEventsSection />

      <DataStateSection />

      <Section title={t('settings.security.recovery')} description={t('settings.security.recoveryDescription')}>
        <Alert>{t('settings.security.recoveryNote')}</Alert>
      </Section>
    </PageBody>
  )
}
