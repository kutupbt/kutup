import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'
import { toast } from 'sonner'
import { useDeleteFolder, useDeleteLabel, usePlaces } from '@kutup/mail-core/places'
import { ConfirmDestructive } from '@kutup/ui/components/confirm-destructive'
import { PlaceDialog } from './PlaceDialog'
import { openPlacesDialog, usePlacesDialog } from './placesState'

/** The folder and label dialogs, and the delete confirmation (Proton's `DeleteLabelModal` texts). */
export function PlacesHost() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const dialog = usePlacesDialog()
  const places = usePlaces()
  const deleteFolder = useDeleteFolder()
  const deleteLabel = useDeleteLabel()
  const close = () => openPlacesDialog(null)
  if (!dialog || !places.data) return null
  if (dialog.kind === 'edit') {
    return <PlaceDialog target={dialog.target} places={places.data} onClose={close} onCreated={dialog.onCreated} />
  }
  const name = dialog.folder?.name ?? dialog.label?.name ?? ''
  const remove = dialog.folder ? deleteFolder : deleteLabel
  return (
    <ConfirmDestructive
      open
      onOpenChange={(open) => !open && close()}
      title={t(dialog.folder ? 'places.deleteFolderTitle' : 'places.deleteLabelTitle')}
      description={t(dialog.folder ? 'places.deleteFolderDescription' : 'places.deleteLabelDescription', { name })}
      submit={t('places.delete')}
      pending={remove.isPending}
      error={remove.error}
      errorFallback={t('common.tryAgain')}
      onConfirm={() => {
        const id = dialog.folder?.id ?? dialog.label!.id
        const done = () => {
          toast.success(t('places.removed', { name }))
          close()
          // Leave a list that no longer exists.
          if (window.location.pathname.startsWith(`/${dialog.folder ? 'f' : 'l'}/${id}`)) void navigate('/inbox')
        }
        if (dialog.folder) deleteFolder.mutate(id, { onSuccess: done })
        else deleteLabel.mutate(id, { onSuccess: done })
      }}
    />
  )
}
