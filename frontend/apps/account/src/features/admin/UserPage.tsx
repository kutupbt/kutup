import { zodResolver } from '@hookform/resolvers/zod'
import { Copy } from 'lucide-react'
import { useEffect, useState, type ReactNode } from 'react'
import { useForm } from 'react-hook-form'
import { useTranslation } from 'react-i18next'
import { useNavigate, useParams } from 'react-router-dom'
import { toast } from 'sonner'
import { z } from 'zod'
import type { UserRow } from '@kutup/session/api-types'
import { useRequiredSession } from '@kutup/session/store'
import { Alert } from '@kutup/ui/components/alert'
import { Badge } from '@kutup/ui/components/badge'
import { Breadcrumb } from '@kutup/ui/components/breadcrumb'
import { Button } from '@kutup/ui/components/button'
import { Card, CardContent } from '@kutup/ui/components/card'
import { ConfirmDestructive } from '@kutup/ui/components/confirm-destructive'
import { Field } from '@kutup/ui/components/field'
import { Input } from '@kutup/ui/components/input'
import { Mono } from '@kutup/ui/components/mono'
import { Fact, PageBody, PageHeader, Section } from '@kutup/ui/components/page'
import { LoadingPanel } from '@kutup/ui/components/states'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { copyText } from '@kutup/ui/lib/clipboard'
import { formatBytes, formatInstant } from '@kutup/ui/lib/format'
import {
  useAdminUsers,
  useDeleteUser,
  useForceDisable2fa,
  useRotateTempPassword,
  useUpdateUser,
  useWipeUser,
} from './api'
import { bytesToGib, generateTempPassword, gibToBytes } from './helpers'
import { UserStatus } from './UsersPage'

function ActionRow({ title, description, action }: { title: string; description: string; action: ReactNode }) {
  return (
    <div className="flex flex-wrap items-center gap-4 p-4">
      <div className="min-w-0 flex-1">
        <p className="font-medium">{title}</p>
        <p className="text-sm text-muted-foreground">{description}</p>
      </div>
      {action}
    </div>
  )
}

function TempPasswordReveal({ password, onClose }: { password: string; onClose: () => void }) {
  const { t } = useTranslation()
  return (
    <Alert variant="warn" title={t('admin.user.newTempPassword')}>
      <div className="mt-2 flex flex-wrap items-center gap-2">
        <Mono className="break-all text-base text-foreground">{password}</Mono>
        <Button size="sm" variant="outline" onClick={() => void copyText(password).then(() => toast.success(t('common.copied')))}>
          <Copy />
          {t('common.copy')}
        </Button>
        <Button size="sm" variant="ghost" onClick={onClose}>
          {t('common.close')}
        </Button>
      </div>
      <p className="mt-2">{t('admin.newUser.handOver')}</p>
    </Alert>
  )
}

function Quotas({ user }: { user: UserRow }) {
  const { t } = useTranslation()
  const update = useUpdateUser()
  const schema = z.object({
    drive: z.coerce.number<number>().positive(t('admin.quota.positive')),
    chat: z.coerce.number<number>().positive(t('admin.quota.positive')),
  })
  const { register, handleSubmit, reset, formState: { errors, isDirty } } = useForm<z.infer<typeof schema>>({
    resolver: zodResolver(schema),
    defaultValues: { drive: bytesToGib(user.storageQuotaBytes), chat: bytesToGib(user.chatStorageQuotaBytes) },
  })
  useEffect(() => {
    reset({ drive: bytesToGib(user.storageQuotaBytes), chat: bytesToGib(user.chatStorageQuotaBytes) })
  }, [user.storageQuotaBytes, user.chatStorageQuotaBytes, reset])

  return (
    <form
      className="space-y-4 p-5"
      onSubmit={(e) =>
        void handleSubmit((v) =>
          update.mutate(
            { id: user.id, patch: { storageQuotaBytes: gibToBytes(v.drive), chatStorageQuotaBytes: gibToBytes(v.chat) } },
            { onSuccess: () => toast.success(t('admin.user.quotasSaved')) },
          ),
        )(e)
      }
      noValidate
    >
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label={t('admin.quota.drive')} error={errors.drive?.message} required>
          {(field) => <Input {...field} {...register('drive')} type="number" min={0.01} step="any" inputMode="decimal" />}
        </Field>
        <Field label={t('admin.quota.chat')} error={errors.chat?.message} required>
          {(field) => <Input {...field} {...register('chat')} type="number" min={0.01} step="any" inputMode="decimal" />}
        </Field>
      </div>
      {update.isError ? <Alert variant="error">{apiErrorMessage(update.error, t('admin.user.saveFailed'))}</Alert> : null}
      <div className="flex justify-end">
        <Button type="submit" loading={update.isPending} disabled={!isDirty}>
          {t('common.save')}
        </Button>
      </div>
    </form>
  )
}

type Pending =
  | { kind: 'disable' }
  | { kind: 'enable' }
  | { kind: 'promote' }
  | { kind: 'demote' }
  | { kind: 'twoFactor' }
  | { kind: 'rotate'; password: string }
  | { kind: 'wipe'; password: string }
  | { kind: 'delete' }

export function UserPage() {
  const { t, i18n } = useTranslation()
  const { id = '' } = useParams()
  const navigate = useNavigate()
  const me = useRequiredSession()
  const users = useAdminUsers()
  const update = useUpdateUser()
  const disable2fa = useForceDisable2fa()
  const rotate = useRotateTempPassword()
  const wipe = useWipeUser()
  const remove = useDeleteUser()
  const [pending, setPending] = useState<Pending | null>(null)
  const [revealed, setRevealed] = useState<string | null>(null)
  const lang = i18n.language

  if (users.isPending) return <LoadingPanel label={t('common.loading')} />
  const user = users.data?.find((u) => u.id === id)
  if (!user) {
    return (
      <PageBody width="prose">
        <Alert variant="error" title={t('admin.user.notFoundTitle')}>
          {users.isError ? apiErrorMessage(users.error, t('common.tryAgain')) : t('admin.user.notFound')}
        </Alert>
      </PageBody>
    )
  }

  const self = user.id === me.userId
  const locked = user.isProtected
  const close = () => {
    setPending(null)
    for (const m of [update, disable2fa, rotate, wipe, remove]) m.reset()
  }

  // One dialog, configured per action. Each confirms only after the server agrees.
  const dialog = (() => {
    if (!pending) return null
    const common = { open: true, onOpenChange: (o: boolean) => !o && close() }
    switch (pending.kind) {
      case 'disable':
      case 'enable': {
        const disabling = pending.kind === 'disable'
        return (
          <ConfirmDestructive {...common}
            title={t(disabling ? 'admin.user.disableTitle' : 'admin.user.enableTitle')}
            description={t(disabling ? 'admin.user.disableDescription' : 'admin.user.enableDescription', { email: user.email })}
            submit={t(disabling ? 'admin.user.disable' : 'admin.user.enable')}
            pending={update.isPending} error={update.error} errorFallback={t('admin.user.saveFailed')}
            onConfirm={() => update.mutate({ id: user.id, patch: { isActive: !disabling } }, { onSuccess: close })} />
        )
      }
      case 'promote':
      case 'demote': {
        const promoting = pending.kind === 'promote'
        return (
          <ConfirmDestructive {...common}
            title={t(promoting ? 'admin.user.promoteTitle' : 'admin.user.demoteTitle')}
            description={t(promoting ? 'admin.user.promoteDescription' : 'admin.user.demoteDescription', { email: user.email })}
            submit={t(promoting ? 'admin.user.promote' : 'admin.user.demote')}
            pending={update.isPending} error={update.error} errorFallback={t('admin.user.saveFailed')}
            onConfirm={() => update.mutate({ id: user.id, patch: { isAdmin: promoting } }, { onSuccess: close })} />
        )
      }
      case 'twoFactor':
        return (
          <ConfirmDestructive {...common}
            title={t('admin.user.twoFactorTitle')}
            description={t('admin.user.twoFactorDescription', { email: user.email })}
            submit={t('admin.user.twoFactorOff')}
            pending={disable2fa.isPending} error={disable2fa.error} errorFallback={t('admin.user.actionFailed')}
            onConfirm={() => disable2fa.mutate(user.id, { onSuccess: () => { toast.success(t('admin.user.twoFactorDone')); close() } })} />
        )
      case 'rotate':
        return (
          <ConfirmDestructive {...common} warningVariant="warn"
            title={t('admin.user.rotateTitle')}
            description={t('admin.user.rotateDescription', { email: user.email })}
            submit={t('admin.user.rotate')}
            pending={rotate.isPending} error={rotate.error} errorFallback={t('admin.user.actionFailed')}
            onConfirm={() => rotate.mutate({ id: user.id, tempPassword: pending.password }, {
              onSuccess: () => { setRevealed(pending.password); close() },
            })} />
        )
      case 'wipe':
        return (
          <ConfirmDestructive {...common}
            title={t('admin.user.wipeTitle')}
            description={t('admin.user.wipeDescription', { email: user.email })}
            warning={t('admin.user.wipeWarning')}
            confirmPhrase={user.email}
            submit={t('admin.user.wipe')}
            pending={wipe.isPending} error={wipe.error} errorFallback={t('admin.user.actionFailed')}
            onConfirm={() => wipe.mutate({ id: user.id, tempPassword: pending.password }, {
              onSuccess: () => { setRevealed(pending.password); close() },
            })} />
        )
      case 'delete':
        return (
          <ConfirmDestructive {...common}
            title={t('admin.user.deleteTitle')}
            description={t('admin.user.deleteDescription', { email: user.email })}
            warning={t('admin.user.deleteWarning')}
            confirmPhrase={user.email}
            submit={t('admin.user.delete')}
            pending={remove.isPending} error={remove.error} errorFallback={t('admin.user.actionFailed')}
            onConfirm={() => remove.mutate(user.id, {
              onSuccess: () => { toast.success(t('admin.user.deleted', { email: user.email })); void navigate('/admin/users') },
            })} />
        )
    }
  })()

  return (
    <PageBody width="prose">
      <Breadcrumb items={[{ label: t('nav.users'), to: '/admin/users' }, { label: user.email }]} />
      <div className="space-y-2">
        <PageHeader title={user.email} />
        <div className="flex flex-wrap items-center gap-2">
          <UserStatus user={user} />
          {user.isAdmin ? <Badge>{t('admin.users.admin')}</Badge> : null}
          {locked ? <Badge variant="neutral">{t('admin.user.protected')}</Badge> : null}
        </div>
      </div>
      {revealed ? <TempPasswordReveal password={revealed} onClose={() => setRevealed(null)} /> : null}

      <Card>
        <CardContent className="grid gap-5 p-5 sm:grid-cols-2">
          <Fact label={t('auth.fields.username')}><Mono>{user.username}</Mono></Fact>
          <Fact label={t('admin.user.created')}>{formatInstant(user.createdAt, lang)}</Fact>
          <Fact label={t('settings.account.driveStorage')}>
            {formatBytes(user.storageUsedBytes, lang)} / {formatBytes(user.storageQuotaBytes, lang)}
          </Fact>
          <Fact label={t('settings.account.chatStorage')}>
            {formatBytes(user.chatStorageUsedBytes, lang)} / {formatBytes(user.chatStorageQuotaBytes, lang)}
          </Fact>
          <Fact label={t('admin.users.columns.twoFactor')}>{user.totpEnabled ? t('admin.users.on') : t('admin.users.off')}</Fact>
        </CardContent>
      </Card>

      {locked ? <Alert>{t('admin.user.protectedNote')}</Alert> : null}

      <Section title={t('admin.user.access')}>
        <Card className="divide-y divide-border p-0">
          <ActionRow
            title={user.isActive ? t('admin.user.disable') : t('admin.user.enable')}
            description={user.isActive ? t('admin.user.disableHint') : t('admin.user.enableHint')}
            action={
              <Button variant="outline" size="sm" disabled={locked || self}
                onClick={() => setPending({ kind: user.isActive ? 'disable' : 'enable' })}>
                {user.isActive ? t('admin.user.disable') : t('admin.user.enable')}
              </Button>
            }
          />
          <ActionRow
            title={user.isAdmin ? t('admin.user.demote') : t('admin.user.promote')}
            description={user.isAdmin ? t('admin.user.demoteHint') : t('admin.user.promoteHint')}
            action={
              <Button variant="outline" size="sm" disabled={locked || (self && user.isAdmin)}
                onClick={() => setPending({ kind: user.isAdmin ? 'demote' : 'promote' })}>
                {user.isAdmin ? t('admin.user.demote') : t('admin.user.promote')}
              </Button>
            }
          />
        </Card>
      </Section>

      <Section title={t('admin.user.quotas')} description={t('admin.user.quotasHint')}>
        <Card className="p-0"><Quotas user={user} /></Card>
      </Section>

      <Section title={t('admin.user.recovery')} description={t('admin.user.recoveryHint')}>
        <Card className="divide-y divide-border p-0">
          {user.totpEnabled ? (
            <ActionRow title={t('admin.user.twoFactorOff')} description={t('admin.user.twoFactorHint')}
              action={<Button variant="outline" size="sm" onClick={() => setPending({ kind: 'twoFactor' })}>{t('admin.user.twoFactorOff')}</Button>} />
          ) : null}
          {user.isFirstLogin ? (
            <ActionRow title={t('admin.user.rotate')} description={t('admin.user.rotateHint')}
              action={<Button variant="outline" size="sm" onClick={() => setPending({ kind: 'rotate', password: generateTempPassword() })}>{t('admin.user.rotate')}</Button>} />
          ) : (
            <ActionRow title={t('admin.user.wipe')} description={t('admin.user.wipeHint')}
              action={<Button variant="outline" size="sm" disabled={locked || self} onClick={() => setPending({ kind: 'wipe', password: generateTempPassword() })}>{t('admin.user.wipe')}</Button>} />
          )}
          <ActionRow title={t('admin.user.delete')} description={t('admin.user.deleteHint')}
            action={<Button variant="destructive" size="sm" disabled={locked || self} onClick={() => setPending({ kind: 'delete' })}>{t('admin.user.delete')}</Button>} />
        </Card>
      </Section>
      {dialog}
    </PageBody>
  )
}
