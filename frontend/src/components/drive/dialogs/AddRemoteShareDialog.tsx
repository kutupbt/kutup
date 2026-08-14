import { useEffect } from 'react'
import { useTranslation } from 'react-i18next'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
  DialogDescription,
} from '@/components/ui/dialog'
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from '@/components/ui/form'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'

interface ParsedInvite {
  server: string
  capability: string
}

function parseInviteLink(value: string): ParsedInvite | null {
  try {
    const url = new URL(value.trim())
    if (url.pathname.replace(/\/+$/, '') !== '/invite') return null
    const fragment = new URLSearchParams(url.hash.replace(/^#/, ''))
    const server = fragment.get('server') ?? ''
    const capability = fragment.get('capability') ?? ''
    if (!/^(?=.{3,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(server)) return null
    if (!/^[A-Za-z0-9._~-]{32,256}$/.test(capability)) return null
    return { server, capability }
  } catch {
    return null
  }
}

const schema = z.object({
  inviteUrl: z.string().refine((value) => parseInviteLink(value) !== null, 'Invalid Kutup invite link'),
})
type FormData = z.infer<typeof schema>

interface Props {
  open: boolean
  onOpenChange: (open: boolean) => void
  onConfirm: (invite: ParsedInvite) => Promise<void>
}

export default function AddRemoteShareDialog({ open, onOpenChange, onConfirm }: Props) {
  const { t } = useTranslation()
  const form = useForm<FormData>({ resolver: zodResolver(schema), defaultValues: { inviteUrl: '' } })

  useEffect(() => {
    if (open) form.reset()
  }, [open])

  async function onSubmit({ inviteUrl }: FormData) {
    const invite = parseInviteLink(inviteUrl)
    if (!invite) return
    await onConfirm(invite)
    onOpenChange(false)
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{t('dialogs.addRemote.title')}</DialogTitle>
          <DialogDescription>
            {t('dialogs.addRemote.description')}
          </DialogDescription>
        </DialogHeader>
        <Form {...form}>
          <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
            <FormField
              control={form.control}
              name="inviteUrl"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t('dialogs.addRemote.inviteLink')}</FormLabel>
                  <FormControl>
                    <Input
                      autoFocus
                      placeholder={t('dialogs.addRemote.placeholder')}
                      autoComplete="off"
                      {...field}
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <DialogFooter>
              <Button variant="outline" type="button" onClick={() => onOpenChange(false)}>
                {t('dialogs.addRemote.cancel')}
              </Button>
              <Button type="submit" disabled={form.formState.isSubmitting}>
                {form.formState.isSubmitting ? t('dialogs.addRemote.adding') : t('dialogs.addRemote.addShare')}
              </Button>
            </DialogFooter>
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  )
}
