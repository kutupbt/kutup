// Kutup's public links as the source supplies them (docs/plans/drive-source.md,
// "Sharing"). The link is made on the person's action, as before the source
// existed: never in an effect, where every change of the dialog's props made one
// more link on the server.

import { useCallback, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import type { Folder } from '@kutup/drive-core/model'
import { useCreatePublicLink } from '@kutup/drive-core/mutations'
import { isTargetBlocked, sharingOffScope } from '@kutup/drive-core/publicSharing'
import type { ItemRef, PublicLinkAction } from '@kutup/drive-source/source'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { LinkDialog } from '../../../features/dialogs/LinkDialog'

/** A public link to a folder: one per `create`, shown once; a toast if it cannot be made. */
export function useKutupPublicLink(): PublicLinkAction {
  const { t } = useTranslation()
  // `mutate` is stable, so `create` is too: a screen may list it as a dependency.
  const { mutate } = useCreatePublicLink()
  const [url, setUrl] = useState<string | null>(null)
  // A second click before the first link is back makes no second link.
  const making = useRef(false)

  const create = useCallback(
    (target: ItemRef) => {
      if (making.current) return
      making.current = true
      mutate(target.folder as Folder, {
        onSuccess: (made) => setUrl(made),
        onError: (error) => {
          const off = sharingOffScope(error)
          toast.error(off ? t(`publicSharing.off.${off}`) : isTargetBlocked(error) ? t('publicSharing.targetBlocked') : apiErrorMessage(error, t('drive.linkFailed')))
        },
        onSettled: () => {
          making.current = false
        },
      })
    },
    [mutate, t],
  )

  return {
    create,
    dialog: (
      <LinkDialog
        link={url}
        title={t('dialogs.publicLink.title')}
        description={t('dialogs.publicLink.description')}
        warning={t('dialogs.publicLink.warning')}
        onClose={() => setUrl(null)}
      />
    ),
  }
}
