import { Camera, Loader2, Trash2 } from 'lucide-react'
import { useEffect, useRef, useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import {
  MLS_GROUP_DESCRIPTION_MAX_CHARS,
  MLS_GROUP_NAME_MAX_CHARS,
  type LocalMlsConversationRecord,
  type MlsGroupInfo,
} from '@kutup/chat-core/types'
import { Button } from '@kutup/ui/components/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { Field } from '@kutup/ui/components/field'
import { Input } from '@kutup/ui/components/input'
import { Textarea } from '@kutup/ui/components/textarea'
import { refreshChat, useChat } from '../../app/chatStore'
import { Avatar } from '../../components/Avatar'
import { GROUP_AVATAR, normalizeAvatar } from '../../lib/avatar'
import { chatErrorMessage } from '../../lib/errors'
import { groupIdOf } from '../../state/views'

/** Characters as people count them (an emoji is one). */
function length(text: string): number {
  return [...text].length
}

/**
 * Signal's "Edit group": picture, name and description. The change is
 * encrypted into the group's state, so only members ever see it.
 */
export function EditGroupInfoDialog({
  group,
  open,
  onOpenChange,
}: {
  group: LocalMlsConversationRecord
  open: boolean
  onOpenChange: (open: boolean) => void
}) {
  const { t } = useTranslation()
  const { service } = useChat()
  const current = group.currentGroupInfo
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [avatar, setAvatar] = useState<MlsGroupInfo['avatar']>()
  const [busy, setBusy] = useState(false)
  const [preparing, setPreparing] = useState(false)
  const picker = useRef<HTMLInputElement>(null)

  // Start from what is stored when opened (or when someone else's change
  // lands meanwhile), not on every reload of the same record.
  const sequence = current?.sequence ?? 0
  useEffect(() => {
    if (!open) return
    setName(current?.name ?? '')
    setDescription(current?.description ?? '')
    setAvatar(current?.avatar)
    // eslint-disable-next-line react-hooks/exhaustive-deps -- keyed by the sequence on purpose
  }, [open, sequence])

  const trimmedName = name.trim()
  const nameTooLong = length(trimmedName) > MLS_GROUP_NAME_MAX_CHARS
  const descriptionTooLong = length(description.trim()) > MLS_GROUP_DESCRIPTION_MAX_CHARS
  const unchanged =
    trimmedName === (current?.name ?? '') &&
    description.trim() === (current?.description ?? '') &&
    avatar?.data === current?.avatar?.data
  const valid = trimmedName.length > 0 && !nameTooLong && !descriptionTooLong

  async function choose(file: File | undefined) {
    if (!file) return
    setPreparing(true)
    try {
      const normalized = await normalizeAvatar(file, GROUP_AVATAR)
      setAvatar({ contentType: normalized.contentType, data: normalized.base64 })
    } catch {
      toast.error(t('chat.group.info.pictureUnreadable'))
    } finally {
      setPreparing(false)
      if (picker.current) picker.current.value = ''
    }
  }

  async function save(event: FormEvent) {
    event.preventDefault()
    if (!service || !valid || unchanged || busy) return
    setBusy(true)
    try {
      await service.setGroupInfo(groupIdOf(group), {
        name: trimmedName,
        ...(description.trim() ? { description: description.trim() } : {}),
        ...(avatar ? { avatar } : {}),
      })
      await refreshChat()
      toast.success(t('chat.group.info.saved'))
      onOpenChange(false)
    } catch (error) {
      toast.error(chatErrorMessage(error, t))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={(next) => !busy && onOpenChange(next)}>
      <DialogContent className="sm:max-w-md" data-testid="chat-group-info-dialog">
        <form onSubmit={(e) => void save(e)} className="space-y-4">
          <DialogHeader>
            <DialogTitle>{t('chat.group.info.title')}</DialogTitle>
            <DialogDescription>{t('chat.group.info.description')}</DialogDescription>
          </DialogHeader>
          <div className="flex items-center gap-4">
            <Avatar name={trimmedName} image={avatar?.data} contentType={avatar?.contentType} group size={80} />
            <div className="flex flex-col gap-2">
              <input
                ref={picker}
                type="file"
                accept="image/png,image/jpeg,image/webp"
                className="hidden"
                onChange={(e) => void choose(e.target.files?.[0])}
                data-testid="chat-group-info-picture-input"
              />
              <Button type="button" variant="outline" size="sm" onClick={() => picker.current?.click()} disabled={preparing || busy}>
                {preparing ? <Loader2 className="animate-spin" /> : <Camera />}
                {avatar ? t('chat.group.info.changePicture') : t('chat.group.info.addPicture')}
              </Button>
              {avatar ? (
                <Button type="button" variant="ghost" size="sm" onClick={() => setAvatar(undefined)} disabled={busy}>
                  <Trash2 />
                  {t('chat.group.info.removePicture')}
                </Button>
              ) : null}
            </div>
          </div>
          <Field
            label={t('chat.group.info.name')}
            error={nameTooLong ? t('chat.group.info.nameTooLong', { count: MLS_GROUP_NAME_MAX_CHARS }) : undefined}
            description={t('chat.group.info.counter', { count: length(trimmedName), max: MLS_GROUP_NAME_MAX_CHARS })}
            required
          >
            {(props) => (
              <Input {...props} value={name} onChange={(e) => setName(e.target.value)} autoComplete="off" data-testid="chat-group-info-name" />
            )}
          </Field>
          <Field
            label={t('chat.group.info.about')}
            error={descriptionTooLong ? t('chat.group.info.aboutTooLong', { count: MLS_GROUP_DESCRIPTION_MAX_CHARS }) : undefined}
            description={t('chat.group.info.counter', { count: length(description.trim()), max: MLS_GROUP_DESCRIPTION_MAX_CHARS })}
          >
            {(props) => (
              <Textarea {...props} rows={3} value={description} onChange={(e) => setDescription(e.target.value)} data-testid="chat-group-info-about" />
            )}
          </Field>
          <DialogFooter>
            <Button type="button" variant="ghost" onClick={() => onOpenChange(false)} disabled={busy}>
              {t('common.cancel')}
            </Button>
            <Button type="submit" disabled={!valid || unchanged || busy || preparing} data-testid="chat-group-info-save">
              {busy ? <Loader2 className="animate-spin" /> : null}
              {t('common.save')}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
