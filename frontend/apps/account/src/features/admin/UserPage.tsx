import { zodResolver } from '@hookform/resolvers/zod'
import { Copy } from 'lucide-react'
import { useEffect, useState, type ReactNode } from 'react'
import { useForm } from 'react-hook-form'
import { useTranslation } from 'react-i18next'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { toast } from 'sonner'
import { z } from 'zod'
import type { SuspendedReason, UserRow } from '@kutup/session/api-types'
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
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@kutup/ui/components/select'
import { Fact, PageBody, PageHeader, Section } from '@kutup/ui/components/page'
import { LoadingPanel } from '@kutup/ui/components/states'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { copyText } from '@kutup/ui/lib/clipboard'
import { formatBytes, formatInstant } from '@kutup/ui/lib/format'
import {
  useAdminUsers,
  useCloseUser,
  useDeleteUser,
  useLegalHold,
  useForceDisable2fa,
  useRotateTempPassword,
  useUpdateUser,
  useUserRegistrationCode,
  useWipeUser,
} from './api'
import { OneUseSecret } from '@kutup/session/reauth'
import { bytesToGib, generateTempPassword, gibToBytes } from './helpers'
import { MailDomainOverridesCard } from './MailDomainOverrides'
import { MailSendingCard } from './MailSending'
import { AccountLimits } from './AccountLimits'
import { UserStatus } from './UsersPage'
import { ReauthLockedError, WrongPasswordError } from '@kutup/session/reauth'

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
    storage: z.coerce.number<number>().positive(t('admin.quota.positive')),
  })
  const { register, handleSubmit, reset, formState: { errors, isDirty } } = useForm<z.infer<typeof schema>>({
    resolver: zodResolver(schema),
    defaultValues: { storage: bytesToGib(user.storageQuotaBytes) },
  })
  useEffect(() => {
    reset({ storage: bytesToGib(user.storageQuotaBytes) })
  }, [user.storageQuotaBytes, reset])

  return (
    <form
      className="space-y-4 p-5"
      onSubmit={(e) =>
        void handleSubmit((v) =>
          update.mutate(
            { id: user.id, patch: { storageQuotaBytes: gibToBytes(v.storage) } },
            { onSuccess: () => toast.success(t('admin.user.quotasSaved')) },
          ),
        )(e)
      }
      noValidate
    >
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label={t('admin.quota.storage')} error={errors.storage?.message} description={t('admin.quota.storageHint')} required>
          {(field) => <Input {...field} {...register('storage')} type="number" min={0.01} step="any" inputMode="decimal" />}
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

const SUSPENDED_REASONS: SuspendedReason[] = ['admin', 'operator_order', 'security']

type Pending =
  | { kind: 'disable' }
  | { kind: 'enable' }
  | { kind: 'promote' }
  | { kind: 'demote' }
  | { kind: 'twoFactor' }
  | { kind: 'rotate'; password: string }
  | { kind: 'wipe'; password: string }
  | { kind: 'delete' }
  | { kind: 'close' }
  | { kind: 'hold' }
  | { kind: 'release' }

/** Which referral code the account signed up with (docs/plans/registration-codes.md). */
function SignedUpWithFact({ userId }: { userId: string }) {
  const { t, i18n } = useTranslation()
  const code = useUserRegistrationCode(userId)
  if (code.isPending || code.isError) return null
  return (
    <Fact label={t('admin.user.signedUpWith')}>
      {code.data ? (
        <>
          <Link to="/admin/codes" className="font-medium text-primary hover:underline">
            <Mono>…{code.data.hint}</Mono>
          </Link>
          {code.data.note ? <span className="text-muted-foreground"> · {code.data.note}</span> : null}
          <div className="text-xs text-muted-foreground">
            {t('admin.user.signedUpWithBy', {
              name: code.data.createdBy ?? t('admin.activity.deletedUser'),
              when: formatInstant(code.data.usedAt, i18n.language),
            })}
          </div>
        </>
      ) : (
        t('admin.user.noReferralCode')
      )}
    </Fact>
  )
}

/** What to say when proving the administrator's password failed, or the action itself. */
function reauthFailure(error: unknown, t: ReturnType<typeof useTranslation>['t']): string {
  if (error instanceof WrongPasswordError) return t('admin.user.wrongAdminPassword')
  if (error instanceof ReauthLockedError) return t(error.reason === 'rateLimited' ? 'admin.user.adminSlowDown' : 'admin.user.adminLocked')
  return t('admin.user.actionFailed')
}

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
  const closeAccount = useCloseUser()
  const legalHold = useLegalHold()
  const [pending, setPending] = useState<Pending | null>(null)
  const [reason, setReason] = useState<SuspendedReason>('admin')
  const [holdReference, setHoldReference] = useState('')
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
    for (const m of [update, disable2fa, rotate, wipe, remove, closeAccount, legalHold]) m.reset()
    setReason('admin')
    setHoldReference('')
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
            description={
              disabling ? (
                <div className="space-y-3">
                  <p>{t('admin.user.disableDescription', { name: user.username })}</p>
                  <Select value={reason} onValueChange={(value) => setReason(value as SuspendedReason)}>
                    <SelectTrigger aria-label={t('admin.user.suspendedReason')}>
                      <SelectValue placeholder={t('admin.user.suspendedReason')} />
                    </SelectTrigger>
                    <SelectContent>
                      {SUSPENDED_REASONS.map((value) => (
                        <SelectItem key={value} value={value}>{t(`admin.user.suspendedReasons.${value}`)}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              ) : (
                t(user.state === 'closing' ? 'admin.user.keepDescription' : 'admin.user.enableDescription', { name: user.username })
              )
            }
            submit={t(disabling ? 'admin.user.disable' : user.state === 'closing' ? 'admin.user.keep' : 'admin.user.enable')}
            pending={update.isPending} error={update.error} errorFallback={t('admin.user.saveFailed')}
            onConfirm={() =>
              update.mutate(
                { id: user.id, patch: disabling ? { isActive: false, suspendedReason: reason } : { isActive: true } },
                { onSuccess: close },
              )} />
        )
      }
      case 'promote':
      case 'demote': {
        const promoting = pending.kind === 'promote'
        return (
          <ConfirmDestructive {...common}
            title={t(promoting ? 'admin.user.promoteTitle' : 'admin.user.demoteTitle')}
            description={t(promoting ? 'admin.user.promoteDescription' : 'admin.user.demoteDescription', { name: user.username })}
            submit={t(promoting ? 'admin.user.promote' : 'admin.user.demote')}
            pending={update.isPending} error={update.error} errorFallback={t('admin.user.saveFailed')}
            onConfirm={() => update.mutate({ id: user.id, patch: { isAdmin: promoting } }, { onSuccess: close })} />
        )
      }
      case 'twoFactor':
        return (
          <ConfirmDestructive {...common}
            title={t('admin.user.twoFactorTitle')}
            description={t('admin.user.twoFactorDescription', { name: user.username })}
            submit={t('admin.user.twoFactorOff')}
            pending={disable2fa.isPending} error={disable2fa.error} errorFallback={t('admin.user.actionFailed')}
            onConfirm={() => disable2fa.mutate(user.id, { onSuccess: () => { toast.success(t('admin.user.twoFactorDone')); close() } })} />
        )
      case 'rotate':
        return (
          <ConfirmDestructive {...common} warningVariant="warn"
            title={t('admin.user.rotateTitle')}
            description={t('admin.user.rotateDescription', { name: user.username })}
            submit={t('admin.user.rotate')}
            passwordLabel={t('admin.user.yourPassword')}
            pending={rotate.isPending} error={rotate.error} errorFallback={reauthFailure(rotate.error, t)}
            onConfirm={(adminPassword) => rotate.mutate({ id: user.id, tempPassword: pending.password, adminPassword: new OneUseSecret(adminPassword) }, {
              onSuccess: () => { setRevealed(pending.password); close() },
            })} />
        )
      case 'wipe':
        return (
          <ConfirmDestructive {...common}
            title={t('admin.user.wipeTitle')}
            description={t('admin.user.wipeDescription', { name: user.username })}
            warning={t('admin.user.wipeWarning')}
            confirmPhrase={user.username}
            submit={t('admin.user.wipe')}
            passwordLabel={t('admin.user.yourPassword')}
            pending={wipe.isPending} error={wipe.error} errorFallback={reauthFailure(wipe.error, t)}
            onConfirm={(adminPassword) => wipe.mutate({ id: user.id, tempPassword: pending.password, adminPassword: new OneUseSecret(adminPassword) }, {
              onSuccess: () => { setRevealed(pending.password); close() },
            })} />
        )
      case 'close':
        return (
          <ConfirmDestructive {...common}
            title={t('admin.user.closeTitle')}
            description={t('admin.user.closeDescription', { name: user.username })}
            confirmPhrase={user.username}
            submit={t('admin.user.close')}
            pending={closeAccount.isPending} error={closeAccount.error} errorFallback={t('admin.user.actionFailed')}
            onConfirm={() => closeAccount.mutate(user.id, { onSuccess: close })} />
        )
      case 'hold':
        return (
          <ConfirmDestructive {...common} warningVariant="warn"
            title={t('admin.user.holdTitle')}
            description={
              <div className="space-y-3">
                <p>{t('admin.user.holdDescription', { name: user.username })}</p>
                <Field label={t('admin.user.holdReference')} required>
                  {(field) => (
                    <Input {...field} value={holdReference} maxLength={200} onChange={(e) => setHoldReference(e.target.value)} />
                  )}
                </Field>
              </div>
            }
            submit={t('admin.user.hold')}
            pending={legalHold.isPending} error={legalHold.error} errorFallback={t('admin.user.saveFailed')}
            onConfirm={() => {
              if (holdReference.trim() === '') return
              legalHold.mutate({ id: user.id, reference: holdReference.trim() }, { onSuccess: close })
            }} />
        )
      case 'release':
        return (
          <ConfirmDestructive {...common} warningVariant="warn"
            title={t('admin.user.releaseTitle')}
            description={t('admin.user.releaseDescription', { name: user.username })}
            submit={t('admin.user.release')}
            pending={legalHold.isPending} error={legalHold.error} errorFallback={t('admin.user.saveFailed')}
            onConfirm={() => legalHold.mutate({ id: user.id, reference: null }, { onSuccess: close })} />
        )
      case 'delete':
        return (
          <ConfirmDestructive {...common}
            title={t('admin.user.deleteTitle')}
            description={t('admin.user.deleteDescription', { name: user.username })}
            warning={t('admin.user.deleteWarning')}
            confirmPhrase={user.username}
            submit={t('admin.user.delete')}
            pending={remove.isPending} error={remove.error} errorFallback={t('admin.user.actionFailed')}
            onConfirm={() => remove.mutate(user.id, {
              onSuccess: () => { toast.success(t('admin.user.deleted', { name: user.username })); void navigate('/admin/users') },
            })} />
        )
    }
  })()

  return (
    <PageBody width="prose">
      <Breadcrumb items={[{ label: t('nav.users'), to: '/admin/users' }, { label: user.username }]} />
      <div className="space-y-2">
        <PageHeader title={user.username} />
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
          <Fact label={t('settings.account.storage')}>
            {formatBytes(user.storageUsedBytes, lang)} / {formatBytes(user.storageQuotaBytes, lang)}
          </Fact>
          <Fact label={t('admin.users.columns.twoFactor')}>{user.totpEnabled ? t('admin.users.on') : t('admin.users.off')}</Fact>
          <SignedUpWithFact userId={user.id} />
          {user.state === 'closing' && user.closesAt ? (
            <Fact label={t('admin.user.closesAt')}>{formatInstant(user.closesAt, lang)}</Fact>
          ) : null}
          {user.state === 'suspended' && user.suspendedReason ? (
            <Fact label={t('admin.user.suspendedReason')}>{t(`admin.user.suspendedReasons.${user.suspendedReason}`)}</Fact>
          ) : null}
        </CardContent>
      </Card>

      {locked ? <Alert>{t('admin.user.protectedNote')}</Alert> : null}
      {user.dataKeyLostAt ? (
        <Alert variant="error">{t('admin.user.dataKeyLost', { date: formatInstant(user.dataKeyLostAt, lang) ?? '' })}</Alert>
      ) : null}
      {user.state === 'closing' && user.deletionAttempts > 0 ? (
        <Alert variant="error">{t('admin.user.deletionFailing', { count: user.deletionAttempts })}</Alert>
      ) : null}

      <Section title={t('admin.user.access')}>
        <Card className="divide-y divide-border p-0">
          {user.state === 'closing' ? (
            <ActionRow
              title={t('admin.user.keep')}
              description={t('admin.user.keepHint')}
              action={
                <Button variant="outline" size="sm" disabled={locked || self} onClick={() => setPending({ kind: 'enable' })}>
                  {t('admin.user.keep')}
                </Button>
              }
            />
          ) : (
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
          )}
          <ActionRow
            title={t(user.publicSharing === 'off' ? 'admin.user.publicLinksOff' : 'admin.user.publicLinksOn')}
            description={t('admin.user.publicLinksHint')}
            action={
              <Button variant="outline" size="sm" disabled={update.isPending}
                onClick={() =>
                  update.mutate(
                    { id: user.id, patch: { publicSharing: user.publicSharing === 'off' ? 'on' : 'off' } },
                    { onError: (error) => toast.error(apiErrorMessage(error, t('admin.user.saveFailed'))) },
                  )
                }>
                {t(user.publicSharing === 'off' ? 'admin.user.publicLinksAllow' : 'admin.user.publicLinksStop')}
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

      <Section title={t('admin.mailSending.title')} description={t('admin.mailSending.cardHint')}>
        <MailSendingCard userId={user.id} />
      </Section>

      <Section title={t('admin.mailDomains.overrides.title')}>
        <MailDomainOverridesCard userId={user.id} />
      </Section>

      <Section title={t('admin.user.quotas')} description={t('admin.user.quotasHint')}>
        <Card className="p-0"><Quotas user={user} /></Card>
      </Section>

      <Section title={t('admin.limits.title')} description={t('admin.limits.hint')}>
        <AccountLimits userId={user.id} />
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
          {user.state !== 'closing' ? (
            <ActionRow title={t('admin.user.close')} description={t('admin.user.closeHint')}
              action={<Button variant="outline" size="sm" disabled={locked || self} onClick={() => setPending({ kind: 'close' })}>{t('admin.user.close')}</Button>} />
          ) : null}
          <ActionRow title={t('admin.user.delete')} description={t(user.legalHoldReference ? 'admin.user.deleteHeldHint' : 'admin.user.deleteHint')}
            action={<Button variant="destructive" size="sm" disabled={locked || self || Boolean(user.legalHoldReference)} onClick={() => setPending({ kind: 'delete' })}>{t('admin.user.delete')}</Button>} />
        </Card>
      </Section>

      <Section title={t('admin.user.legalHold')} description={t('admin.user.legalHoldHint')}>
        <Card className="p-0">
          {user.legalHoldReference ? (
            <ActionRow
              title={t('admin.user.heldSince', { date: formatInstant(user.legalHoldAt ?? null, lang) ?? '' })}
              description={user.legalHoldReference}
              action={<Button variant="outline" size="sm" onClick={() => setPending({ kind: 'release' })}>{t('admin.user.release')}</Button>}
            />
          ) : (
            <ActionRow
              title={t('admin.user.notHeld')}
              description={t('admin.user.notHeldHint')}
              action={<Button variant="outline" size="sm" onClick={() => setPending({ kind: 'hold' })}>{t('admin.user.hold')}</Button>}
            />
          )}
        </Card>
      </Section>
      {dialog}
    </PageBody>
  )
}
