import { useTranslation } from 'react-i18next'
import {
  AlertDialog,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@kutup/ui/components/alert-dialog'
import { Button } from '@kutup/ui/components/button'

/**
 * Signal's "Delete message?": for me (gone from all of this account's
 * devices, nobody else's), or, for your own messages, for everyone (a
 * "This message was deleted" in its place for all).
 */
export function DeleteMessageDialog({
  open,
  onOpenChange,
  forEveryone,
  onDeleteForMe,
  onDeleteForEveryone,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  /** Offer "Delete for everyone" (the message is this account's own). */
  forEveryone: boolean
  onDeleteForMe: () => void
  onDeleteForEveryone: () => void
}) {
  const { t } = useTranslation()
  return (
    <AlertDialog open={open} onOpenChange={onOpenChange}>
      <AlertDialogContent data-testid="chat-delete-dialog">
        <AlertDialogHeader>
          <AlertDialogTitle>{t('chat.mutations.deleteTitle')}</AlertDialogTitle>
          <AlertDialogDescription>
            {forEveryone ? t('chat.mutations.deleteChoice') : t('chat.mutations.deleteForMeOnly')}
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel>{t('common.cancel')}</AlertDialogCancel>
          <Button variant="destructive" onClick={onDeleteForMe} data-testid="chat-delete-for-me">
            {t('chat.mutations.deleteForMe')}
          </Button>
          {forEveryone ? (
            <Button variant="destructive" onClick={onDeleteForEveryone} data-testid="chat-delete-for-everyone">
              {t('chat.mutations.deleteForEveryone')}
            </Button>
          ) : null}
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  )
}
