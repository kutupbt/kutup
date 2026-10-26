import { zodResolver } from '@hookform/resolvers/zod'
import { useEffect } from 'react'
import { Controller, useForm } from 'react-hook-form'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { z } from 'zod'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Card, CardContent } from '@kutup/ui/components/card'
import { Field } from '@kutup/ui/components/field'
import { Input } from '@kutup/ui/components/input'
import { PageBody, PageHeader, Section } from '@kutup/ui/components/page'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@kutup/ui/components/select'
import { LoadingPanel } from '@kutup/ui/components/states'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import type { AdminSettings, RegistrationMode, RegistrySetting, SettingSection } from '@kutup/session/api-types'
import { SETTING_LABELS } from './AccountLimits'
import { useAdminSettings, useSettingsRegistry, useUpdateAdminSettings } from './api'
import { Choice } from './federation/Choice'
import { bytesToGib, gibToBytes } from './helpers'

const MODES: readonly RegistrationMode[] = ['on', 'code', 'off']

/** The server's bounds (site_settings::validate_chat_delivery_retention_days). */
const MAX_RETENTION_DAYS = 3650
/** The server's bounds (site_settings::validate_chat_group_link_joins_per_relay). */
const MAX_LINK_JOINS = 1_000_000
/**
 * The avatar blob lengths (kutup_chat_proto GROUP_AVATAR_BLOB_LENGTHS) and the
 * server's bounds (site_settings::AvatarLimits): storage holds two of the
 * largest avatar (a swap needs the old and the new), at most two of 41001.
 */
const AVATAR_LENGTHS = [8233, 16425, 32809, 41001] as const
const MAX_AVATAR_STORAGE = 2 * 41001
const AVATAR_PENDING_SECONDS = { min: 60, max: 7 * 24 * 3600 } as const


/** The largest Pass vault upload is set in MiB. */
const MIB = 1024 * 1024

export function ServerSettingsPage() {
  const { t } = useTranslation()
  const settings = useAdminSettings()
  const registry = useSettingsRegistry()
  if (settings.isPending || registry.isPending) return <LoadingPanel label={t('common.loading')} />
  if (settings.isError || registry.isError) {
    return <PageBody width="prose"><Alert variant="error">{apiErrorMessage(settings.error ?? registry.error, t('common.tryAgain'))}</Alert></PageBody>
  }
  return <ServerSettingsForm settings={settings.data} registry={registry.data} />
}

/**
 * The form, once the settings and the registry are in: its whole-number
 * fields, with their ranges, come from the registry.
 */
function ServerSettingsForm({ settings, registry }: { settings: AdminSettings; registry: RegistrySetting[] }) {
  const { t } = useTranslation()
  const update = useUpdateAdminSettings()
  const inSection = (section: SettingSection) => registry.filter((setting) => setting.section === section)

  const days = z.coerce.number<number>().int(t('admin.settings.wholeDays')).min(0, t('admin.settings.retentionRange')).max(MAX_RETENTION_DAYS, t('admin.settings.retentionRange'))
  const linkJoins = z.coerce.number<number>().int(t('admin.settings.groupLinkJoinsRange')).min(1, t('admin.settings.groupLinkJoinsRange')).max(MAX_LINK_JOINS, t('admin.settings.groupLinkJoinsRange'))
  const schema = z.object({
    registrationMode: z.enum(['on', 'code', 'off']),
    quotaGib: z.coerce.number<number>().positive(t('admin.quota.positive')),
    mailboxDays: days,
    mediaDays: days,
    linkJoinsGroup: linkJoins,
    linkJoinsRelay: linkJoins,
    numeric: z.object(
      Object.fromEntries(
        registry.map(({ field, min, max }) => {
          const range = t('admin.settings.multi.range', { min, max })
          return [field, z.coerce.number<number>().int(range).min(min, range).max(max, range)]
        }),
      ) as Record<string, z.ZodNumber>,
    ),
    avatarMax: z.coerce.number<number>().refine((value) => (AVATAR_LENGTHS as readonly number[]).includes(value), t('admin.settings.groupAvatarMaxRange')),
    avatarStorage: z.coerce.number<number>().int(t('admin.settings.groupAvatarStorageRange')).max(MAX_AVATAR_STORAGE, t('admin.settings.groupAvatarStorageRange')),
    avatarPending: z.coerce.number<number>().int(t('admin.settings.groupAvatarPendingRange')).min(AVATAR_PENDING_SECONDS.min, t('admin.settings.groupAvatarPendingRange')).max(AVATAR_PENDING_SECONDS.max, t('admin.settings.groupAvatarPendingRange')),
    passVaultMib: z.coerce.number<number>().int(t('admin.settings.passVaultMaxRange')).min(1, t('admin.settings.passVaultMaxRange')).max(1024, t('admin.settings.passVaultMaxRange')),
  }).refine((v) => v.avatarStorage >= 2 * v.avatarMax, { path: ['avatarStorage'], message: t('admin.settings.groupAvatarStorageRange') })
  const { register, control, handleSubmit, reset, formState: { errors, isDirty } } = useForm<z.infer<typeof schema>>({
    resolver: zodResolver(schema),
  })
  useEffect(() => {
    reset({
      registrationMode: settings.registrationMode,
      quotaGib: bytesToGib(settings.defaultStorageQuotaBytes),
      mailboxDays: settings.chatMailboxRetentionDays,
      mediaDays: settings.chatMediaDeliveryRetentionDays,
      linkJoinsGroup: settings.chatGroupLinkJoinsPerRelayGroupPerMin,
      linkJoinsRelay: settings.chatGroupLinkJoinsPerRelayPerMin,
      numeric: Object.fromEntries(registry.map(({ field }) => [field, settings[field] as number])),
      avatarMax: settings.chatGroupAvatarMaxBytes,
      avatarStorage: settings.chatGroupAvatarStoragePerGroupBytes,
      avatarPending: settings.chatGroupAvatarPendingSeconds,
      passVaultMib: Math.round(settings.passVaultMaxBytes / MIB),
    })
  }, [settings, registry, reset])

  const onSubmit = handleSubmit((v) =>
    update.mutate(
      {
        registrationMode: v.registrationMode,
        defaultStorageQuotaBytes: gibToBytes(v.quotaGib),
        chatMailboxRetentionDays: v.mailboxDays,
        chatMediaDeliveryRetentionDays: v.mediaDays,
        chatGroupLinkJoinsPerRelayGroupPerMin: v.linkJoinsGroup,
        chatGroupLinkJoinsPerRelayPerMin: v.linkJoinsRelay,
        ...v.numeric,
        chatGroupAvatarMaxBytes: v.avatarMax,
        chatGroupAvatarStoragePerGroupBytes: v.avatarStorage,
        chatGroupAvatarPendingSeconds: v.avatarPending,
        passVaultMaxBytes: v.passVaultMib * MIB,
      },
      { onSuccess: () => toast.success(t('admin.settings.saved')) },
    ),
  )

  /** A section's whole-number fields, as the registry lists them. */
  const numericFields = (section: SettingSection) =>
    inSection(section).map(({ field, min, max }) => (
      <Field key={field} label={t(`${SETTING_LABELS[section]}.${field}`)} error={errors.numeric?.[field]?.message} description={t(`${SETTING_LABELS[section]}.${field}Hint`)} required>
        {(control) => <Input {...control} {...register(`numeric.${field}`)} type="number" min={min} max={max} step={1} inputMode="numeric" />}
      </Field>
    ))

  return (
    <PageBody width="prose">
      <PageHeader title={t('admin.settings.title')} description={t('admin.settings.description')} />
      <form className="space-y-6" onSubmit={(e) => void onSubmit(e)} noValidate>
        <Section title={t('admin.settings.accounts')}>
          <Card>
            <CardContent className="p-5">
              <div className="max-w-sm">
                <Field label={t('admin.settings.registration')} description={t('admin.settings.registrationHint')}>
                  {() => (
                    <Controller
                      control={control}
                      name="registrationMode"
                      render={({ field }) => (
                        <Choice value={field.value} options={MODES} labelPrefix="admin.settings.registrationMode" onChange={field.onChange} ariaLabel={t('admin.settings.registration')} />
                      )}
                    />
                  )}
                </Field>
              </div>
              <div className="mt-5 max-w-xs">
                <Field label={t('admin.settings.defaultQuota')} error={errors.quotaGib?.message} description={t('admin.settings.defaultQuotaHint')} required>
                  {(field) => <Input {...field} {...register('quotaGib')} type="number" min={0.01} step="any" inputMode="decimal" />}
                </Field>
              </div>
            </CardContent>
          </Card>
        </Section>
        <Section title={t('admin.settings.chat')} description={t('admin.settings.chatHint')}>
          <Card>
            <CardContent className="grid gap-4 p-5 sm:grid-cols-2">
              <Field label={t('admin.settings.mailboxDays')} error={errors.mailboxDays?.message} description={t('admin.settings.mailboxDaysHint')} required>
                {(field) => <Input {...field} {...register('mailboxDays')} type="number" min={0} max={MAX_RETENTION_DAYS} step={1} inputMode="numeric" />}
              </Field>
              <Field label={t('admin.settings.mediaDays')} error={errors.mediaDays?.message} description={t('admin.settings.mediaDaysHint')} required>
                {(field) => <Input {...field} {...register('mediaDays')} type="number" min={0} max={MAX_RETENTION_DAYS} step={1} inputMode="numeric" />}
              </Field>
              <Field label={t('admin.settings.groupLinkJoinsGroup')} error={errors.linkJoinsGroup?.message} description={t('admin.settings.groupLinkJoinsGroupHint')} required>
                {(field) => <Input {...field} {...register('linkJoinsGroup')} type="number" min={1} max={MAX_LINK_JOINS} step={1} inputMode="numeric" />}
              </Field>
              <Field label={t('admin.settings.groupLinkJoinsRelay')} error={errors.linkJoinsRelay?.message} description={t('admin.settings.groupLinkJoinsRelayHint')} required>
                {(field) => <Input {...field} {...register('linkJoinsRelay')} type="number" min={1} max={MAX_LINK_JOINS} step={1} inputMode="numeric" />}
              </Field>
              {numericFields('chatMulti')}
              <Field label={t('admin.settings.groupAvatarMax')} error={errors.avatarMax?.message} description={t('admin.settings.groupAvatarMaxHint')} required>
                {(field) => (
                  <Controller
                    control={control}
                    name="avatarMax"
                    render={({ field: value }) => (
                      <Select value={value.value === undefined ? undefined : String(value.value)} onValueChange={(next) => value.onChange(Number(next))}>
                        <SelectTrigger id={field.id} aria-describedby={field['aria-describedby']}>
                          <SelectValue placeholder={t('admin.settings.groupAvatarMax')} />
                        </SelectTrigger>
                        <SelectContent>
                          {AVATAR_LENGTHS.map((length) => <SelectItem key={length} value={String(length)}>{t('admin.settings.groupAvatarBytes', { count: length })}</SelectItem>)}
                        </SelectContent>
                      </Select>
                    )}
                  />
                )}
              </Field>
              <Field label={t('admin.settings.groupAvatarStorage')} error={errors.avatarStorage?.message} description={t('admin.settings.groupAvatarStorageHint')} required>
                {(field) => <Input {...field} {...register('avatarStorage')} type="number" min={2 * AVATAR_LENGTHS[0]} max={MAX_AVATAR_STORAGE} step={1} inputMode="numeric" />}
              </Field>
              <Field label={t('admin.settings.groupAvatarPending')} error={errors.avatarPending?.message} description={t('admin.settings.groupAvatarPendingHint')} required>
                {(field) => <Input {...field} {...register('avatarPending')} type="number" min={AVATAR_PENDING_SECONDS.min} max={AVATAR_PENDING_SECONDS.max} step={1} inputMode="numeric" />}
              </Field>
            </CardContent>
          </Card>
        </Section>
        <Section title={t('admin.settings.pass')} description={t('admin.settings.passHint')}>
          <Card>
            <CardContent className="grid gap-4 p-5 sm:grid-cols-2">
              <Field label={t('admin.settings.passVaultMax')} error={errors.passVaultMib?.message} description={t('admin.settings.passVaultMaxHint')} required>
                {(field) => <Input {...field} {...register('passVaultMib')} type="number" min={1} max={1024} step={1} inputMode="numeric" />}
              </Field>
            </CardContent>
          </Card>
        </Section>
        <Section title={t('admin.settings.calendar')} description={t('admin.settings.calendarHint')}>
          <Card>
            <CardContent className="grid gap-4 p-5 sm:grid-cols-2">
              {numericFields('calendar')}
            </CardContent>
          </Card>
        </Section>
        <Section title={t('admin.settings.drive')} description={t('admin.settings.driveHint')}>
          <Card>
            <CardContent className="grid gap-4 p-5 sm:grid-cols-2">
              {numericFields('drive')}
            </CardContent>
          </Card>
        </Section>
        <Section title={t('admin.settings.chatLinking')} description={t('admin.settings.chatLinkingHint')}>
          <Card>
            <CardContent className="grid gap-4 p-5 sm:grid-cols-2">
              {numericFields('chatLinking')}
            </CardContent>
          </Card>
        </Section>
        <Section title={t('admin.settings.twoFactor')} description={t('admin.settings.twoFactorHint')}>
          <Card>
            <CardContent className="grid gap-4 p-5 sm:grid-cols-2">
              {numericFields('twoFactor')}
            </CardContent>
          </Card>
        </Section>
        {update.isError ? <Alert variant="error">{apiErrorMessage(update.error, t('admin.settings.saveFailed'))}</Alert> : null}
        <div className="flex justify-end">
          <Button type="submit" loading={update.isPending} disabled={!isDirty}>{t('common.save')}</Button>
        </div>
      </form>
    </PageBody>
  )
}
