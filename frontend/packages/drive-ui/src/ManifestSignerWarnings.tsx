import { useEffect } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { watchManifestSigners } from '@kutup/drive-core/manifestSigners'

/**
 * Warns when a file this page opens was not signed by the person its
 * manifest names, or was signed under keys other than the ones the user
 * knows for them (docs/plans/drive-block-format.md §2, "The signature").
 * The file still opens: Drive warns, it does not refuse, as for its other
 * signatures (docs/plans/drive-identity-pins.md). Mounted once per app,
 * beside its toaster.
 */
export function ManifestSignerWarnings() {
  const { t } = useTranslation()
  useEffect(
    () =>
      watchManifestSigners(({ kind, name }) => {
        const message =
          kind === 'forged'
            ? name
              ? t('identityCheck.content.forged', { name })
              : t('identityCheck.content.forgedUnnamed')
            : name
              ? t('identityCheck.content.changed', { name })
              : t('identityCheck.content.changedUnnamed')
        toast.warning(message, { duration: Infinity, closeButton: true })
      }),
    [t],
  )
  return null
}
