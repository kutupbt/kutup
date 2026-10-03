import { BookImage, Check, Plus } from 'lucide-react'
import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Button } from '@kutup/ui/components/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { Field } from '@kutup/ui/components/field'
import { Input } from '@kutup/ui/components/input'
import { cn } from '@kutup/ui/lib/cn'
import type { Photo } from '../library/library'
import { useAddToAlbum, useAlbums, useCreateAlbum } from './albums'

/** Put photos in one of your albums, or in a new one. */
export function AddToAlbumDialog({ photos, open, onClose, onAdded }: { photos: Photo[]; open: boolean; onClose: () => void; onAdded: () => void }) {
  const { t } = useTranslation()
  const all = useAlbums()
  // Albums this account may put photos in: its own, and shared ones that allow it.
  const albums = { data: all.data?.filter((a) => a.canAdd) }
  const add = useAddToAlbum()
  const create = useCreateAlbum()
  // An album's id, or 'new'.
  const [chosen, setChosen] = useState<string | null>(null)
  const [name, setName] = useState('')
  useEffect(() => {
    if (open) {
      setChosen((albums.data?.length ?? 0) > 0 ? null : 'new')
      setName('')
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps -- reset each time it opens
  }, [open])

  const pending = add.isPending || create.isPending
  const done = (albumName: string) => {
    toast.success(t('albums.added', { count: photos.length, album: albumName }))
    onAdded()
    onClose()
  }
  const submit = () => {
    if (chosen === 'new') {
      if (!name.trim()) return
      create.mutate({ name, photos }, { onSuccess: () => done(name.trim()), onError: () => toast.error(t('albums.failed')) })
      return
    }
    const album = albums.data?.find((a) => a.id === chosen)
    if (album) add.mutate({ album, photos }, { onSuccess: () => done(album.name), onError: () => toast.error(t('albums.failed')) })
  }

  return (
    <Dialog open={open} onOpenChange={(v) => !v && onClose()}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{t('albums.addTitle', { count: photos.length })}</DialogTitle>
          <DialogDescription>{t('albums.addDescription')}</DialogDescription>
        </DialogHeader>
        <form
          className="space-y-3"
          onSubmit={(e) => {
            e.preventDefault()
            submit()
          }}
        >
          <ul className="max-h-72 space-y-1 overflow-y-auto" role="radiogroup" aria-label={t('albums.title')}>
            {(albums.data ?? []).map((album) => (
              <li key={album.id}>
                <button
                  type="button"
                  role="radio"
                  aria-checked={chosen === album.id}
                  onClick={() => setChosen(album.id)}
                  className={cn(
                    'flex w-full items-center gap-3 rounded-md border px-3 py-2 text-left text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
                    chosen === album.id ? 'border-primary bg-primary/5' : 'border-border hover:bg-accent',
                  )}
                >
                  <BookImage className="size-4 text-muted-foreground" aria-hidden />
                  <span className="min-w-0 flex-1 truncate">{album.name}</span>
                  {chosen === album.id ? <Check className="size-4 text-primary" aria-hidden /> : null}
                </button>
              </li>
            ))}
            <li>
              <button
                type="button"
                role="radio"
                aria-checked={chosen === 'new'}
                onClick={() => setChosen('new')}
                className={cn(
                  'flex w-full items-center gap-3 rounded-md border px-3 py-2 text-left text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
                  chosen === 'new' ? 'border-primary bg-primary/5' : 'border-border hover:bg-accent',
                )}
              >
                <Plus className="size-4 text-muted-foreground" aria-hidden />
                <span className="flex-1">{t('albums.new')}</span>
              </button>
            </li>
          </ul>
          {chosen === 'new' ? (
            <Field label={t('albums.name')}>
              {(field) => <Input {...field} autoFocus value={name} maxLength={200} onChange={(e) => setName(e.target.value)} />}
            </Field>
          ) : null}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose}>
              {t('common.cancel')}
            </Button>
            <Button type="submit" disabled={pending || !chosen || (chosen === 'new' && !name.trim())}>
              {pending ? t('albums.adding') : t('albums.add')}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
