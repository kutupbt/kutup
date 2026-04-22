import { useEffect } from 'react'
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

const schema = z.object({
  inviteUrl: z.string().url('Must be a valid URL'),
})
type FormData = z.infer<typeof schema>

interface Props {
  open: boolean
  onOpenChange: (open: boolean) => void
  onConfirm: (inviteUrl: string) => Promise<void>
}

export default function AddRemoteShareDialog({ open, onOpenChange, onConfirm }: Props) {
  const form = useForm<FormData>({ resolver: zodResolver(schema), defaultValues: { inviteUrl: '' } })

  useEffect(() => {
    if (open) form.reset()
  }, [open])

  async function onSubmit({ inviteUrl }: FormData) {
    await onConfirm(inviteUrl.trim())
    onOpenChange(false)
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Add remote share</DialogTitle>
          <DialogDescription>
            Paste the invite link you received from someone on another Kutup server.
          </DialogDescription>
        </DialogHeader>
        <Form {...form}>
          <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
            <FormField
              control={form.control}
              name="inviteUrl"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Invite link</FormLabel>
                  <FormControl>
                    <Input
                      autoFocus
                      placeholder="https://other-server.com/invite/…"
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
                Cancel
              </Button>
              <Button type="submit" disabled={form.formState.isSubmitting}>
                {form.formState.isSubmitting ? 'Adding…' : 'Add share'}
              </Button>
            </DialogFooter>
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  )
}
