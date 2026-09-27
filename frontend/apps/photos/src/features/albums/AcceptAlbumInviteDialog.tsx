import { useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'
import { toast } from 'sonner'
import { parseInvite, useAcceptInvite } from '@kutup/drive-core/mutations'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { Field } from '@kutup/ui/components/field'
import { Input } from '@kutup/ui/components/input'
import { apiErrorCode, apiErrorMessage } from '@kutup/ui/lib/apiError'
import { useQueryClient } from '@tanstack/react-query'
import { albumsKey } from './albums'

/**
 * Paste the invite link someone on another Kutup server sent for an album.
 * Only album invites are taken here; folders and files are added in Drive.
 */
export function AcceptAlbumInviteDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const accept = useAcceptInvite()
  const [value, setValue] = useState('')
  const invite = parseInvite(value)
  const notAlbum = invite !== null && invite.kind !== 'album'

  function submit(event: FormEvent) {
    event.preventDefault()
    if (!invite || notAlbum) return
    accept.mutate(invite, {
      onSuccess: (result) => {
        void queryClient.invalidateQueries({ queryKey: albumsKey }).then(() => {
          toast.success(t('albums.invite.added'))
          setValue('')
          onClose()
          void navigate(`/albums/${result.id}`)
        })
      },
    })
  }

  const fieldError = value.trim() && !invite ? t('albums.invite.invalid') : notAlbum ? t('albums.invite.notAlbum') : undefined
  const error = accept.error
    ? apiErrorCode(accept.error) === 'not_found'
      ? t('albums.invite.notFound')
      : apiErrorCode(accept.error) === 'forbidden'
        ? t('albums.invite.notForYou')
        : apiErrorMessage(accept.error, t('albums.invite.failed'))
    : null

  return (
    <Dialog open={open} onOpenChange={(o) => !o && (accept.reset(), onClose())}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{t('albums.invite.title')}</DialogTitle>
          <DialogDescription>{t('albums.invite.description')}</DialogDescription>
        </DialogHeader>
        <form className="space-y-4" onSubmit={submit}>
          <Field label={t('albums.invite.link')} error={fieldError} required>
            {(field) => (
              <Input
                {...field}
                value={value}
                onChange={(e) => setValue(e.target.value)}
                autoFocus
                autoComplete="off"
                spellCheck={false}
                className="font-mono text-xs"
                placeholder="https://…/invite#server=…&capability=…&kind=album"
              />
            )}
          </Field>
          {error ? <Alert variant="error">{error}</Alert> : null}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose}>
              {t('common.cancel')}
            </Button>
            <Button type="submit" loading={accept.isPending} disabled={!invite || notAlbum}>
              {t('albums.invite.submit')}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
