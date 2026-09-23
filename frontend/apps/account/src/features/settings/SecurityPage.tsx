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
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { useDisableTotp, useStartTotp, useVerifyTotp, type TotpEnrolment } from './api'

function CodeField({
  label,
  value,
  onChange,
}: {
  label: string
  value: string
  onChange: (value: string) => void
}) {
  return (
    <Field label={label} required>
      {(field) => (
        <Input
          {...field}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          autoComplete="one-time-code"
          inputMode="numeric"
          maxLength={6}
          className="max-w-40 font-mono tracking-widest"
        />
      )}
    </Field>
  )
}

function Enrol() {
  const { t } = useTranslation()
  const start = useStartTotp()
  const verify = useVerifyTotp()
  const [enrolment, setEnrolment] = useState<TotpEnrolment | null>(null)
  const [code, setCode] = useState('')

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
    verify.mutate(code.trim(), {
      onSuccess: () => {
        toast.success(t('settings.security.enabled'))
        setEnrolment(null)
        setCode('')
      },
    })
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
      </ol>
      {verify.isError ? (
        <Alert variant="error">{apiErrorMessage(verify.error, t('settings.security.verifyFailed'))}</Alert>
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
        disable.mutate(code.trim(), {
          onSuccess: () => {
            toast.success(t('settings.security.disabled'))
            setOpen(false)
            setCode('')
          },
        })
      }}
    >
      <Alert variant="warn">{t('settings.security.disableWarning')}</Alert>
      <CodeField label={t('settings.security.code')} value={code} onChange={setCode} />
      {disable.isError ? (
        <Alert variant="error">{apiErrorMessage(disable.error, t('settings.security.disableFailed'))}</Alert>
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
            {session.totpEnabled ? <Disable /> : <Enrol />}
          </CardContent>
        </Card>
      </Section>

      <Section title={t('settings.security.recovery')} description={t('settings.security.recoveryDescription')}>
        <Alert>{t('settings.security.recoveryNote')}</Alert>
      </Section>
    </PageBody>
  )
}
