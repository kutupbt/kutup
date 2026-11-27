// Kutup's sharing dialogs as the source supplies them (docs/plans/drive-source.md,
// "Sharing"). Each wraps Kutup's own dialog, unchanged: identity pins, the
// key-rotation review and federation stay in them and read drive-core and the
// pins themselves. The screens pass only the item and whether it is open.

import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import type { DriveFile, Folder } from '@kutup/drive-core/model'
import { FileShareDialog } from '@kutup/drive-ui/FileShareDialog'
import type { ItemRef } from '@kutup/drive-source/source'
import { LinkDialog } from '../../../features/dialogs/LinkDialog'
import { AcceptInviteDialog } from './AcceptInviteDialog'
import { ShareDialog } from './ShareDialog'

export interface SlotProps {
  open: boolean
  onOpenChange: (open: boolean) => void
}

/** A federated invite, shown once to send to the person on the other server. */
function InviteDialog({ invite, onClose }: { invite: { url: string; account: string } | null; onClose: () => void }) {
  const { t } = useTranslation()
  return (
    <LinkDialog
      link={invite?.url ?? null}
      title={t('dialogs.invite.title')}
      description={t('dialogs.invite.description', { account: invite?.account ?? '' })}
      warning={t('dialogs.invite.warning')}
      onClose={onClose}
    />
  )
}

/**
 * Sharing a folder (ShareDialog, with its access list) or a file by itself
 * (FileShareDialog: as its owner, or as an editor the owner lets share a file
 * shared with them, which is in no folder of theirs).
 */
export function KutupShareDialog({ target, open, onOpenChange }: SlotProps & { target: ItemRef | null }) {
  const [invite, setInvite] = useState<{ url: string; account: string } | null>(null)
  const close = () => onOpenChange(false)
  const shown = open ? target : null
  return (
    <>
      <ShareDialog folder={shown && !shown.file ? (shown.folder as Folder) : null} onClose={close} onInvite={(url, account) => setInvite({ url, account })} />
      <FileShareDialog
        target={
          shown?.file
            ? { folder: shown.folder as Folder, file: shown.file as DriveFile, role: shown.folder.source === 'file' ? ('editor' as const) : ('owner' as const) }
            : null
        }
        onClose={close}
      />
      <InviteDialog invite={invite} onClose={() => setInvite(null)} />
    </>
  )
}

/** Opening an invite from another server (a pasted link or code). */
export function KutupAcceptInviteDialog({ open, onOpenChange }: SlotProps) {
  return <AcceptInviteDialog open={open} onClose={() => onOpenChange(false)} />
}
