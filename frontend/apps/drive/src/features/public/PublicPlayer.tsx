import { Suspense } from 'react'
import { useTranslation } from 'react-i18next'
import { usePlaybackOf } from '@kutup/drive-core/playback'
import { openPublicFilePlayback, type PublicFile } from '@kutup/editors/public/share'
import { chooseViewer } from '@kutup/editors/viewers/dispatch'
import { Dialog, DialogContent, DialogDescription, DialogTitle } from '@kutup/ui/components/dialog'
import { Spinner } from '@kutup/ui/components/states'

/**
 * A video or song from a public link, played where it is listed: streamed
 * by block through the service worker with the link's key
 * (docs/plans/drive-block-format.md §4), or read whole where no worker
 * controls the page.
 */
export function PublicPlayer({ token, file, onClose }: { token: string; file: PublicFile; onClose: () => void }) {
  const { t } = useTranslation()
  const name = file.name ?? ''
  const viewer = chooseViewer(name)
  const playback = usePlaybackOf((signal, onProgress) => openPublicFilePlayback(token, file, signal, onProgress), `${token}/${file.row.id}`)
  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="max-w-3xl">
        <DialogTitle className="truncate pr-8 text-base">{name}</DialogTitle>
        <DialogDescription className="sr-only">{t('public.player.description')}</DialogDescription>
        <div className="mt-4 flex min-h-40 items-center justify-center">
          {playback.kind === 'ready' && viewer ? (
            <Suspense fallback={<Spinner label={t('public.player.loading')} />}>
              <viewer.Component filename={name} blobUrl={playback.src} mimeType={viewer.mimeType} />
            </Suspense>
          ) : playback.kind === 'loading' ? (
            <Spinner label={t('public.player.loading')} />
          ) : (
            <p className="text-sm text-muted-foreground">{t(`quickLook.none.${playback.kind === 'tooLarge' ? 'size' : playback.kind}`)}</p>
          )}
        </div>
      </DialogContent>
    </Dialog>
  )
}
