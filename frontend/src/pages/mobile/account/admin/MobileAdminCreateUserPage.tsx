import { useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { Loader2 } from 'lucide-react'
import { MobileShell } from '@/components/mobile/MobileShell'
import { MobilePageHeader } from '@/components/mobile/MobilePageHeader'
import { Icon, ICONS } from '@/components/mobile/Icon'
import { Surface } from '@/components/ui/surface'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { useCreateUser } from '@/api/hooks/useAdmin'
import { useIsMobile } from '@/hooks/useIsMobile'
import { cn } from '@/lib/utils'

/**
 * MobileAdminCreateUserPage — `/drive/account/admin/new-user`.
 *
 * Full page (not a sheet — per the user's "tap-on-something-clickable
 * goes to a full page" rule). Form: email + username + temporary
 * password + quota preset.
 *
 * Differences from the design's mock form:
 *  - **Temp password field added** — kutup's `POST /admin/users`
 *    requires it. The new user changes it on first sign-in.
 *  - **"Make admin on create" toggle dropped** — backend doesn't
 *    accept it on create today. Promote post-create when PR 12.1
 *    lands the `isAdmin` field on the update endpoint.
 *  - **"Send welcome email" toggle dropped** — kutup has no welcome-
 *    email path; toggling it would be a lie.
 */

const QUOTA_PRESETS = [
  { label: '1 GB', gb: 1 },
  { label: '5 GB', gb: 5 },
  { label: '10 GB', gb: 10 },
  { label: '50 GB', gb: 50 },
  { label: '100 GB', gb: 100 },
] as const

const formSchema = z.object({
  email: z.string().email('Invalid email'),
  username: z
    .string()
    .min(3, 'At least 3 characters')
    .max(32)
    .regex(/^[a-z0-9_-]+$/, 'Lowercase letters, numbers, _ and - only'),
  tempPassword: z.string().min(8, 'At least 8 characters'),
  quotaGB: z.number().min(1).max(10_000),
})
type FormShape = z.infer<typeof formSchema>

export default function MobileAdminCreateUserPage() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const isMobile = useIsMobile()
  const createUser = useCreateUser()

  useEffect(() => {
    if (!isMobile) navigate('/admin', { replace: true })
  }, [isMobile, navigate])

  const form = useForm<FormShape>({
    resolver: zodResolver(formSchema),
    defaultValues: { email: '', username: '', tempPassword: '', quotaGB: 10 },
  })

  const quotaGB = form.watch('quotaGB')

  async function onSubmit(values: FormShape) {
    await createUser.mutateAsync({
      email: values.email,
      username: values.username,
      tempPassword: values.tempPassword,
      storageQuotaBytes: values.quotaGB * 1024 * 1024 * 1024,
    })
    form.reset()
    navigate('/drive/account/admin', { replace: true })
  }

  if (!isMobile) return null

  return (
    <MobileShell>
      <MobilePageHeader
        title={t('mobile.admin.createUser.title', 'New user')}
        back
        onBack={() => navigate('/drive/account/admin')}
      />
      <form
        onSubmit={form.handleSubmit(onSubmit)}
        className="flex-1 overflow-auto px-3.5 pt-4 pb-24"
      >
        <p className="text-[12.5px] text-text-tertiary mb-4 leading-relaxed">
          {t(
            'mobile.admin.createUser.intro',
            'A temporary password is set now; the user replaces it on first sign-in and generates encryption keys client-side.',
          )}
        </p>

        {/* Account */}
        <div className="text-[11.5px] font-semibold tracking-[0.06em] uppercase text-text-tertiary px-1 pb-2">
          {t('mobile.admin.createUser.accountSection', 'Account')}
        </div>
        <Surface className="mb-4 p-3.5">
          <div className="mb-3">
            <label className="block text-[11.5px] font-semibold tracking-[0.04em] uppercase text-text-tertiary mb-1.5">
              {t('mobile.admin.createUser.email', 'Email')}
            </label>
            <Input
              type="email"
              autoComplete="off"
              placeholder="name@kutup.cloud"
              {...form.register('email')}
            />
            {form.formState.errors.email && (
              <p className="text-[12px] text-destructive mt-1">{form.formState.errors.email.message}</p>
            )}
          </div>
          <div className="mb-3">
            <label className="block text-[11.5px] font-semibold tracking-[0.04em] uppercase text-text-tertiary mb-1.5">
              {t('mobile.admin.createUser.username', 'Username')}
            </label>
            <Input
              type="text"
              autoComplete="off"
              autoCapitalize="off"
              placeholder="short-handle"
              {...form.register('username')}
            />
            {form.formState.errors.username && (
              <p className="text-[12px] text-destructive mt-1">{form.formState.errors.username.message}</p>
            )}
          </div>
          <div>
            <label className="block text-[11.5px] font-semibold tracking-[0.04em] uppercase text-text-tertiary mb-1.5">
              {t('mobile.admin.createUser.tempPassword', 'Temporary password')}
            </label>
            <Input
              type="text"
              autoComplete="off"
              placeholder={t('mobile.admin.createUser.tempPasswordPlaceholder', 'min 8 characters')}
              {...form.register('tempPassword')}
            />
            <p className="text-[11px] text-text-tertiary mt-1">
              {t(
                'mobile.admin.createUser.tempPasswordHint',
                'Share this with the user out-of-band; they change it on first sign-in.',
              )}
            </p>
            {form.formState.errors.tempPassword && (
              <p className="text-[12px] text-destructive mt-1">{form.formState.errors.tempPassword.message}</p>
            )}
          </div>
        </Surface>

        {/* Quota presets */}
        <div className="text-[11.5px] font-semibold tracking-[0.06em] uppercase text-text-tertiary px-1 pb-2">
          {t('mobile.admin.createUser.quotaSection', 'Quota')}
        </div>
        <Surface className="mb-5 p-3">
          <div className="flex gap-1.5 flex-wrap">
            {QUOTA_PRESETS.map((q) => {
              const active = quotaGB === q.gb
              return (
                <button
                  key={q.gb}
                  type="button"
                  onClick={() => form.setValue('quotaGB', q.gb)}
                  className={cn(
                    'flex-1 min-w-[60px] h-9 rounded-lg text-[12.5px] font-medium cursor-pointer border transition-colors',
                    active
                      ? 'bg-primary text-white border-primary'
                      : 'bg-surface text-text-primary border-border hover:bg-surface-raised',
                  )}
                >
                  {q.label}
                </button>
              )
            })}
          </div>
        </Surface>

        {/* Submit row */}
        <div className="flex gap-2">
          <Button
            type="button"
            variant="outline"
            className="flex-1 h-12 min-h-tap"
            onClick={() => navigate('/drive/account/admin')}
          >
            {t('common.cancel', 'Cancel')}
          </Button>
          <Button
            type="submit"
            className="flex-[2] h-12 min-h-tap gap-1.5"
            disabled={createUser.isPending || form.formState.isSubmitting}
          >
            {(createUser.isPending || form.formState.isSubmitting) && (
              <Loader2 className="h-4 w-4 animate-spin" />
            )}
            <Icon d={ICONS.userPlus} size={15} />
            {t('mobile.admin.createUser.submit', 'Create user')}
          </Button>
        </div>
      </form>
    </MobileShell>
  )
}
