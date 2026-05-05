import { useEffect } from 'react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
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

const schema = z.object({
  name: z
    .string()
    .min(1, 'Name is required')
    .max(255, 'Name is too long')
    .refine((v) => !v.includes('/') && !v.includes('\\'), 'No slashes allowed'),
})
type FormData = z.infer<typeof schema>

interface Props {
  open: boolean
  onOpenChange: (open: boolean) => void
  onConfirm: (filename: string) => Promise<void>
}

export default function NewNoteDialog({ open, onOpenChange, onConfirm }: Props) {
  const form = useForm<FormData>({
    resolver: zodResolver(schema),
    defaultValues: { name: 'Untitled.md' },
  })

  useEffect(() => {
    if (open) form.reset({ name: 'Untitled.md' })
  }, [open])

  async function onSubmit({ name }: FormData) {
    let final = name.trim()
    if (!final.toLowerCase().endsWith('.md')) final = `${final}.md`
    await onConfirm(final)
    onOpenChange(false)
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-sm">
        <DialogHeader>
          <DialogTitle>New note</DialogTitle>
          <DialogDescription>Creates an empty Markdown file you can edit collaboratively.</DialogDescription>
        </DialogHeader>
        <Form {...form}>
          <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
            <FormField
              control={form.control}
              name="name"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Filename</FormLabel>
                  <FormControl>
                    <Input
                      autoFocus
                      onFocus={(e) => {
                        // Select just the filename, leaving .md preserved.
                        const v = e.currentTarget.value
                        const dot = v.lastIndexOf('.')
                        e.currentTarget.setSelectionRange(0, dot >= 0 ? dot : v.length)
                      }}
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
                Create &amp; open
              </Button>
            </DialogFooter>
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  )
}
