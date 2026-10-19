import { Loader2 } from 'lucide-react'
import { useMemo, useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'
import { toast } from 'sonner'
import { Button } from '@kutup/ui/components/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { Field } from '@kutup/ui/components/field'
import { Input } from '@kutup/ui/components/input'
import { refreshChat, useChat } from '../../app/chatStore'
import { chatErrorMessage } from '../../lib/errors'
import { personName } from '../../lib/names'
import { ContactPicker } from '../details/ChatGroupDetails'
import { pathForConversation } from './paths'

/** A title's longest (Signal's group name limit). */
const TITLE_MAX = 32

/**
 * A new group (docs/plans/pairwise-groups.md), as Signal starts one: a name
 * and the contacts to invite. It lives on this account's server, with this
 * account its first administrator; the people chosen get an invitation to
 * accept. Only contacts can be invited, as Signal adds only people whose
 * profile it holds.
 */
export function NewGroupDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const { service, snapshot, self } = useChat()
  const [name, setName] = useState('')
  const [chosen, setChosen] = useState<string[]>([])
  const [busy, setBusy] = useState(false)
  const selfKey = self?.key ?? ''
  const profiles = useMemo(() => new Map(snapshot.profiles.map((p) => [p.peer, p])), [snapshot.profiles])
  const candidates = snapshot.contacts.filter((c) => c.state === 'accepted' && c.peer !== selfKey).map((c) => c.peer)
  const tooLong = [...name.trim()].length > TITLE_MAX

  function close() {
    onOpenChange(false)
    setName('')
    setChosen([])
  }

  async function create(event: FormEvent) {
    event.preventDefault()
    if (!service || tooLong || !name.trim()) return
    setBusy(true)
    try {
      const created = await service.createChatGroup(name.trim(), chosen)
      await refreshChat()
      close()
      if (!created.titleSet) toast.error(t('chat.chatGroup.titleNotSet'))
      if (created.invited < chosen.length) {
        toast.error(t('chat.chatGroup.someNotInvited', { count: chosen.length - created.invited }))
      }
      toast.success(t('chat.group.created'))
      void navigate(pathForConversation({ kind: 'group', groupId: created.groupId }))
    } catch (cause) {
      toast.error(chatErrorMessage(cause, t))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={(next) => (next ? onOpenChange(true) : close())}>
      <DialogContent className="sm:max-w-md">
        <form onSubmit={(e) => void create(e)} className="space-y-4">
          <DialogHeader>
            <DialogTitle>{t('chat.group.newTitle')}</DialogTitle>
            <DialogDescription>{t('chat.chatGroup.newDescription')}</DialogDescription>
          </DialogHeader>
          <Field
            label={t('chat.group.info.name')}
            description={t('chat.group.info.counter', { count: [...name.trim()].length, max: TITLE_MAX })}
            error={tooLong ? t('chat.group.info.nameTooLong', { count: TITLE_MAX }) : undefined}
            required
          >
            {(props) => (
              <Input
                {...props}
                autoFocus
                autoComplete="off"
                value={name}
                onChange={(e) => setName(e.target.value)}
                data-testid="chat-group-name"
              />
            )}
          </Field>
          <div className="space-y-2">
            <p className="text-sm font-medium">{t('chat.chatGroup.chooseMembers')}</p>
            <ContactPicker
              candidates={candidates}
              chosen={chosen}
              onChange={setChosen}
              nameOf={(account) => personName(account, profiles, selfKey, t)}
            />
          </div>
          <DialogFooter>
            <Button type="button" variant="ghost" onClick={close}>
              {t('common.cancel')}
            </Button>
            <Button type="submit" disabled={!name.trim() || tooLong || busy} data-testid="chat-group-create-submit">
              {busy ? <Loader2 className="animate-spin" /> : null}
              {t('chat.group.create')}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
