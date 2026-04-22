import { useState } from 'react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { Globe } from 'lucide-react'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
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
import { Alert, AlertDescription } from '@/components/ui/alert'
import type { Collection } from '@/types/drive'

const schema = z.object({
  recipient: z.string().min(1, 'Recipient is required'),
  canUpload: z.boolean(),
  canDelete: z.boolean(),
  quotaGB: z.string(),
})
type FormData = z.infer<typeof schema>

function isFederated(val: string): boolean {
  const at = val.lastIndexOf('@')
  if (at < 0) return false
  return val.slice(at + 1).includes('.')
}

interface Props {
  collection: Collection | null
  onOpenChange: (open: boolean) => void
  onShare: (params: {
    recipient: string
    canUpload: boolean
    canDelete: boolean
    quotaBytes: number | null
    isFederated: boolean
  }) => Promise<void>
}

export default function ShareDialog({ collection, onOpenChange, onShare }: Props) {
  const form = useForm<FormData>({
    resolver: zodResolver(schema),
    defaultValues: { recipient: '', canUpload: false, canDelete: false, quotaGB: '' },
  })

  const recipient = form.watch('recipient')
  const canUpload = form.watch('canUpload')
  const federated = isFederated(recipient)

  async function onSubmit(data: FormData) {
    const quotaBytes = data.canUpload && data.quotaGB.trim()
      ? Math.round(parseFloat(data.quotaGB) * 1024 * 1024 * 1024)
      : null
    await onShare({
      recipient: data.recipient.trim(),
      canUpload: data.canUpload,
      canDelete: data.canDelete,
      quotaBytes,
      isFederated: isFederated(data.recipient.trim()),
    })
    form.reset()
    onOpenChange(false)
  }

  return (
    <Dialog open={collection !== null} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Share "{collection?.decryptedName}"</DialogTitle>
        </DialogHeader>
        <Form {...form}>
          <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
            <FormField
              control={form.control}
              name="recipient"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Recipient</FormLabel>
                  <FormControl>
                    <Input
                      autoFocus
                      placeholder="email@example.com or alice@other-server.com"
                      autoComplete="email"
                      {...field}
                    />
                  </FormControl>
                  {federated && (
                    <div className="flex items-center gap-1.5 text-xs text-primary mt-1">
                      <Globe className="h-3.5 w-3.5" />
                      Federated share — will generate an invite link
                    </div>
                  )}
                  <FormMessage />
                </FormItem>
              )}
            />

            <div className="space-y-2">
              <p className="text-sm font-medium">Permissions</p>
              <label className="flex items-center gap-2 text-sm text-muted-foreground">
                <input type="checkbox" checked disabled className="opacity-50" />
                Download (always on)
              </label>
              <div className="space-y-2">
                <FormField
                  control={form.control}
                  name="canUpload"
                  render={({ field }) => (
                    <div className="flex items-center gap-2">
                      <input
                        type="checkbox"
                        id="share-upload"
                        checked={field.value}
                        onChange={(e) => {
                          field.onChange(e.target.checked)
                          if (!e.target.checked) form.setValue('quotaGB', '')
                        }}
                      />
                      <label htmlFor="share-upload" className="text-sm cursor-pointer">
                        Upload
                      </label>
                      {field.value && (
                        <FormField
                          control={form.control}
                          name="quotaGB"
                          render={({ field: qf }) => (
                            <Input
                              type="number"
                              placeholder="Quota GB (blank = unlimited)"
                              className="h-7 w-44 text-xs"
                              min="0"
                              step="any"
                              {...qf}
                            />
                          )}
                        />
                      )}
                    </div>
                  )}
                />
                <FormField
                  control={form.control}
                  name="canDelete"
                  render={({ field }) => (
                    <div className="flex items-center gap-2">
                      <input
                        type="checkbox"
                        id="share-delete"
                        checked={field.value}
                        onChange={field.onChange}
                      />
                      <label htmlFor="share-delete" className="text-sm cursor-pointer">
                        Delete own uploads
                      </label>
                    </div>
                  )}
                />
              </div>
            </div>

            <DialogFooter>
              <Button variant="outline" type="button" onClick={() => { form.reset(); onOpenChange(false) }}>
                Cancel
              </Button>
              <Button type="submit" disabled={form.formState.isSubmitting}>
                {federated ? 'Share & get invite link' : 'Share'}
              </Button>
            </DialogFooter>
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  )
}
