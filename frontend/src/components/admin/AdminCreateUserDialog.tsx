import { useTranslation } from 'react-i18next'
import { useForm, type Resolver } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { Loader2 } from 'lucide-react'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from '@/components/ui/form'
import { useCreateUser } from '@/api/hooks/useAdmin'
import { cn } from '@/lib/utils'

/**
 * AdminCreateUserDialog — extracted from the old monolithic Admin.tsx.
 *
 * Same fields as before (email + username + tempPassword + quota in GB),
 * dressed up to match the design's create-user modal:
 *  - Quota presets row (1 / 5 / 10 / 50 / 100 GB) clickable above the input.
 *  - Drops the design's "Make admin" toggle (no backend support today).
 *  - Drops the design's "Send welcome email" toggle (kutup has no welcome
 *    email flow).
 *
 * The temp-password field is intentionally NOT optional — kutup requires
 * it; the new user replaces it on first sign-in and generates encryption
 * keys client-side.
 */

const PRESETS_GB = [1, 5, 10, 50, 100] as const

const createUserSchema = z.object({
  email: z.string().email('Invalid email'),
  username: z
    .string()
    .min(3, 'At least 3 characters')
    .max(32)
    .regex(/^[a-z0-9_-]+$/, 'Lowercase letters, numbers, _ and - only'),
  tempPassword: z.string().min(1, 'Required'),
  quotaGB: z.coerce.number().min(1, 'At least 1 GB'),
})

type CreateUserForm = z.infer<typeof createUserSchema>

interface AdminCreateUserDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
}

export function AdminCreateUserDialog({ open, onOpenChange }: AdminCreateUserDialogProps) {
  const { t } = useTranslation()
  const createUser = useCreateUser()

  const form = useForm<CreateUserForm>({
    resolver: zodResolver(createUserSchema) as Resolver<CreateUserForm>,
    defaultValues: { email: '', username: '', tempPassword: '', quotaGB: 10 },
  })

  const quotaGB = form.watch('quotaGB')

  async function onSubmit(data: CreateUserForm) {
    await createUser.mutateAsync({
      email: data.email,
      username: data.username,
      tempPassword: data.tempPassword,
      storageQuotaBytes: data.quotaGB * 1024 * 1024 * 1024,
    })
    form.reset()
    onOpenChange(false)
  }

  return (
    <Dialog open={open} onOpenChange={(v) => { if (!v) form.reset(); onOpenChange(v) }}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{t('admin.createDialog.title', 'Create user')}</DialogTitle>
          <DialogDescription>
            {t(
              'admin.createDialog.desc',
              'A temporary password is set now; the user replaces it on first sign-in.',
            )}
          </DialogDescription>
        </DialogHeader>

        <Form {...form}>
          <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
            <FormField
              control={form.control}
              name="email"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t('admin.createDialog.email', 'Email')}</FormLabel>
                  <FormControl>
                    <Input type="email" autoComplete="email" placeholder="name@kutup.cloud" {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="username"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t('admin.createDialog.username', 'Username')}</FormLabel>
                  <FormControl>
                    <Input
                      placeholder={t('admin.createDialog.usernamePlaceholder', 'short-handle')}
                      {...field}
                      onChange={(e) => field.onChange(e.target.value.toLowerCase())}
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="tempPassword"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t('admin.createDialog.tempPassword', 'Temporary password')}</FormLabel>
                  <FormControl>
                    <Input
                      placeholder={t('admin.createDialog.tempPasswordPlaceholder', 'min 8 characters')}
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
              name="quotaGB"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t('admin.createDialog.quotaLabel', 'Quota')}</FormLabel>
                  <div className="flex gap-1.5 mb-2">
                    {PRESETS_GB.map((p) => {
                      const active = quotaGB === p
                      return (
                        <button
                          key={p}
                          type="button"
                          onClick={() => form.setValue('quotaGB', p)}
                          className={cn(
                            'flex-1 h-9 rounded-lg text-[12.5px] font-medium cursor-pointer border transition-colors',
                            active
                              ? 'bg-primary text-white border-primary'
                              : 'bg-surface text-text-primary border-border hover:bg-surface-raised',
                          )}
                        >
                          {p} GB
                        </button>
                      )
                    })}
                  </div>
                  <FormControl>
                    <Input type="number" min="1" step="1" {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <DialogFooter>
              <Button
                variant="outline"
                type="button"
                onClick={() => { form.reset(); onOpenChange(false) }}
              >
                {t('admin.createDialog.cancel', 'Cancel')}
              </Button>
              <Button type="submit" disabled={form.formState.isSubmitting}>
                {form.formState.isSubmitting && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
                {t('admin.createDialog.create', 'Create user')}
              </Button>
            </DialogFooter>
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  )
}
