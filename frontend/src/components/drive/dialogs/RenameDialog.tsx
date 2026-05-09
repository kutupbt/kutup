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
import type { Collection, DecryptedFile } from '@/types/drive'
import { splitFilename, joinFilename } from '@/lib/filename'

const schema = z.object({
  name: z.string().min(1, 'Name is required').max(255),
})
type FormData = z.infer<typeof schema>

export type RenameTarget =
  | { kind: 'collection'; collection: Collection }
  | { kind: 'file'; file: DecryptedFile }

interface Props {
  target: RenameTarget | null
  onOpenChange: (open: boolean) => void
  onConfirmCollection: (col: Collection, newName: string) => Promise<void>
  onConfirmFile: (file: DecryptedFile, newName: string) => Promise<void>
}

export default function RenameDialog({
  target,
  onOpenChange,
  onConfirmCollection,
  onConfirmFile,
}: Props) {
  const { t } = useTranslation()

  // For files with a known extension, we lock the extension and only
  // allow editing the base — protects office/text dispatch from a user
  // accidentally turning report.docx into report.txt.
  const initialName =
    target?.kind === 'collection'
      ? target.collection.decryptedName ?? ''
      : target?.kind === 'file'
        ? target.file.decryptedName ?? ''
        : ''
  const split = target?.kind === 'file' ? splitFilename(initialName) : null
  const lockedExt = split?.ext ?? ''
  const initialBase = split ? split.base : initialName

  const form = useForm<FormData>({
    resolver: zodResolver(schema),
    defaultValues: { name: initialBase },
  })

  useEffect(() => {
    form.reset({ name: initialBase })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [target?.kind, target && (target.kind === 'collection' ? target.collection.id : target.file.id)])

  async function onSubmit({ name }: FormData) {
    if (!target) return
    const trimmed = name.trim()
    if (target.kind === 'collection') {
      await onConfirmCollection(target.collection, trimmed)
    } else {
      const final = lockedExt ? joinFilename(trimmed, lockedExt) : trimmed
      await onConfirmFile(target.file, final)
    }
    onOpenChange(false)
  }

  const titleKey = target?.kind === 'file' ? 'dialogs.rename.titleFile' : 'dialogs.rename.titleFolder'

  return (
    <Dialog open={target !== null} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-sm">
        <DialogHeader>
          <DialogTitle>{t(titleKey, { defaultValue: t('dialogs.rename.title') })}</DialogTitle>
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
                    {lockedExt ? (
                      <div className="flex items-center gap-1 rounded-md border border-input bg-background pr-2 focus-within:ring-2 focus-within:ring-ring">
                        <Input
                          autoFocus
                          {...field}
                          className="flex-1 border-0 focus-visible:ring-0 focus-visible:ring-offset-0"
                        />
                        <span className="text-sm text-muted-foreground select-none">.{lockedExt}</span>
                      </div>
                    ) : (
                      <Input autoFocus {...field} />
                    )}
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
