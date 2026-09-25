import { Loader2 } from 'lucide-react'
import { useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'
import { toast } from 'sonner'
import { parseAccountAddress, withHomeServer } from '@kutup/chat-core/identity'
import { MLS_GROUP_NAME_MAX_CHARS } from '@kutup/chat-core/types'
import { Button } from '@kutup/ui/components/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { Field } from '@kutup/ui/components/field'
import { Input } from '@kutup/ui/components/input'
import { refreshChat, useChat } from '../../app/chatStore'
import { chatErrorMessage } from '../../lib/errors'
import { groupIdOf } from '../../state/views'
import { pathForConversation } from './paths'

/**
 * A new private (MLS) group, started with one other member; more are added
 * from the group's details. This account becomes its administrator and owner.
 */
export function NewGroupDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const { service, capabilities } = useChat()
  const [name, setName] = useState('')
  const [value, setValue] = useState('')
  const [error, setError] = useState<string | undefined>()
  const [busy, setBusy] = useState(false)

  function close() {
    onOpenChange(false)
    setName('')
    setValue('')
    setError(undefined)
  }

  async function create(event: FormEvent) {
    event.preventDefault()
    const parsed = parseAccountAddress(value)
    const member = parsed ? withHomeServer(parsed, capabilities?.serverName) : null
    if (!member?.server || !service) {
      setError(t('chat.errors.invalidAddress'))
      return
    }
    setBusy(true)
    try {
      const group = await service.createGroup(member, name.trim())
      await refreshChat()
      close()
      toast.success(t('chat.group.created'))
      void navigate(pathForConversation({ kind: 'group', groupId: groupIdOf(group) }))
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
            <DialogDescription>{t('chat.group.newDescription')}</DialogDescription>
          </DialogHeader>
          <Field
            label={t('chat.group.info.name')}
            description={t('chat.group.info.counter', { count: [...name.trim()].length, max: MLS_GROUP_NAME_MAX_CHARS })}
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
          <Field label={t('chat.group.firstMember')} error={error}>
            {(props) => (
              <Input
                {...props}
                autoComplete="off"
                spellCheck={false}
                placeholder={t('chat.username')}
                value={value}
                onChange={(e) => {
                  setValue(e.target.value)
                  setError(undefined)
                }}
                data-testid="chat-group-initial-member"
              />
            )}
          </Field>
          <DialogFooter>
            <Button type="button" variant="ghost" onClick={close}>
              {t('common.cancel')}
            </Button>
            <Button
              type="submit"
              disabled={!value.trim() || !name.trim() || [...name.trim()].length > MLS_GROUP_NAME_MAX_CHARS || busy}
              data-testid="chat-group-create-submit"
            >
              {busy ? <Loader2 className="animate-spin" /> : null}
              {t('chat.group.create')}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
