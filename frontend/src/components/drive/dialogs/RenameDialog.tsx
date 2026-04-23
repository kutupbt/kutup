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
import type { Collection } from '@/types/drive'

const schema = z.object({
  name: z.string().min(1, 'Name is required').max(255),
})
type FormData = z.infer<typeof schema>

interface Props {
  collection: Collection | null
  onOpenChange: (open: boolean) => void
  onConfirm: (col: Collection, newName: string) => Promise<void>
}

export default function RenameDialog({ collection, onOpenChange, onConfirm }: Props) {
  const { t } = useTranslation()
  const form = useForm<FormData>({
    resolver: zodResolver(schema),
    defaultValues: { name: collection?.decryptedName ?? '' },
  })

  useEffect(() => {
    if (collection) form.reset({ name: collection.decryptedName ?? '' })
  }, [collection])

  async function onSubmit({ name }: FormData) {
    if (!collection) return
    await onConfirm(collection, name.trim())
    onOpenChange(false)
  }

  return (
    <Dialog open={collection !== null} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-sm">
        <DialogHeader>
          <DialogTitle>{t('dialogs.rename.title')}</DialogTitle>
        </DialogHeader>
        <Form {...form}>
          <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
            <FormField
              control={form.control}
              name="name"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t('dialogs.rename.newName')}</FormLabel>
                  <FormControl>
                    <Input autoFocus {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <DialogFooter>
              <Button variant="outline" type="button" onClick={() => onOpenChange(false)}>
                {t('dialogs.rename.cancel')}
              </Button>
              <Button type="submit" disabled={form.formState.isSubmitting}>
                {t('dialogs.rename.rename')}
              </Button>
            </DialogFooter>
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  )
}
