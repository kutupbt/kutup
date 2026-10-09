import { zodResolver } from '@hookform/resolvers/zod'
import { Copy, RefreshCw } from 'lucide-react'
import { useState } from 'react'
import { useForm } from 'react-hook-form'
import { useTranslation } from 'react-i18next'
import { Link, useNavigate } from 'react-router-dom'
import { toast } from 'sonner'
import { z } from 'zod'
import { Alert } from '@kutup/ui/components/alert'
import { Breadcrumb } from '@kutup/ui/components/breadcrumb'
import { Button } from '@kutup/ui/components/button'
import { Card, CardContent } from '@kutup/ui/components/card'
import { Field } from '@kutup/ui/components/field'
import { Input } from '@kutup/ui/components/input'
import { Mono } from '@kutup/ui/components/mono'
import { PageBody, PageHeader } from '@kutup/ui/components/page'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { copyText } from '@kutup/ui/lib/clipboard'
import { useCreateUser } from './api'
import { generateTempPassword, gibToBytes } from './helpers'

/** Mirrors the server's username rule. */
const USERNAME = /^[a-z0-9_-]{3,32}$/

export function NewUserPage() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const create = useCreateUser()
  const [created, setCreated] = useState<{ email: string; tempPassword: string } | null>(null)

  const schema = z.object({
    email: z.string().trim().min(1, t('auth.validation.emailRequired')).includes('@', { message: t('auth.validation.emailInvalid') }),
    username: z.string().trim().regex(USERNAME, t('auth.validation.username')),
    tempPassword: z.string().min(1, t('admin.newUser.tempPasswordRequired')),
    storageQuotaGib: z.coerce.number<number>().positive(t('admin.quota.positive')),
  })
  const {
    register,
    handleSubmit,
    setValue,
    getValues,
    formState: { errors },
  } = useForm<z.infer<typeof schema>>({
    resolver: zodResolver(schema),
    defaultValues: { email: '', username: '', tempPassword: generateTempPassword(), storageQuotaGib: 10 },
  })

  const onSubmit = handleSubmit((values) => {
    create.mutate(
      {
        email: values.email.trim(),
        username: values.username.trim(),
        tempPassword: values.tempPassword,
        storageQuotaBytes: gibToBytes(values.storageQuotaGib),
      },
      { onSuccess: () => setCreated({ email: values.email.trim(), tempPassword: values.tempPassword }) },
    )
  })

  const crumbs = (
    <Breadcrumb items={[{ label: t('nav.users'), to: '/admin/users' }, { label: t('admin.newUser.title') }]} />
  )

  if (created) {
    return (
      <PageBody width="prose">
        {crumbs}
        <PageHeader title={t('admin.newUser.createdTitle')} description={t('admin.newUser.createdDescription', { email: created.email })} />
        <Card>
          <CardContent className="space-y-4 p-5">
            <div className="flex flex-wrap items-center gap-3 rounded-md border border-border bg-muted/40 p-3">
              <Mono className="flex-1 break-all text-base">{created.tempPassword}</Mono>
              <Button
                variant="outline"
                size="sm"
                onClick={() => void copyText(created.tempPassword).then(() => toast.success(t('common.copied')))}
              >
                <Copy />
                {t('common.copy')}
              </Button>
            </div>
            <Alert variant="warn">{t('admin.newUser.handOver')}</Alert>
            <Button onClick={() => void navigate('/admin/users')}>{t('admin.newUser.done')}</Button>
          </CardContent>
        </Card>
      </PageBody>
    )
  }

  return (
    <PageBody width="prose">
      {crumbs}
      <PageHeader title={t('admin.newUser.title')} description={t('admin.newUser.description')} />
      {create.isError ? <Alert variant="error">{apiErrorMessage(create.error, t('admin.newUser.failed'))}</Alert> : null}
      <Card>
        <CardContent className="p-5">
          <form className="space-y-4" onSubmit={(e) => void onSubmit(e)} noValidate>
            <div className="grid gap-4 sm:grid-cols-2">
              <Field label={t('auth.fields.email')} error={errors.email?.message} required>
                {(field) => <Input {...field} {...register('email')} type="email" autoComplete="off" autoFocus />}
              </Field>
              <Field label={t('auth.fields.username')} error={errors.username?.message} required>
                {(field) => <Input {...field} {...register('username')} autoComplete="off" autoCapitalize="off" spellCheck={false} />}
              </Field>
            </div>
            <Field
              label={t('admin.newUser.tempPassword')}
              error={errors.tempPassword?.message}
              description={t('admin.newUser.tempPasswordHint')}
              required
            >
              {(field) => (
                <div className="flex gap-2">
                  <Input {...field} {...register('tempPassword')} className="font-mono" autoComplete="off" spellCheck={false} />
                  <Button
                    type="button"
                    variant="outline"
                    size="icon"
                    aria-label={t('admin.newUser.regenerate')}
                    onClick={() => setValue('tempPassword', generateTempPassword(), { shouldValidate: true })}
                  >
                    <RefreshCw />
                  </Button>
                  <Button
                    type="button"
                    variant="outline"
                    size="icon"
                    aria-label={t('common.copy')}
                    onClick={() => void copyText(getValues('tempPassword')).then(() => toast.success(t('common.copied')))}
                  >
                    <Copy />
                  </Button>
                </div>
              )}
            </Field>
            <div className="grid gap-4 sm:grid-cols-2">
              <Field label={t('admin.quota.storage')} error={errors.storageQuotaGib?.message} description={t('admin.quota.storageHint')} required>
                {(field) => <Input {...field} {...register('storageQuotaGib')} type="number" min={0.01} step="any" inputMode="decimal" />}
              </Field>
            </div>
            <div className="flex justify-end gap-2 pt-2">
              <Button variant="outline" asChild>
                <Link to="/admin/users">{t('common.cancel')}</Link>
              </Button>
              <Button type="submit" loading={create.isPending}>
                {t('admin.newUser.submit')}
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>
    </PageBody>
  )
}
