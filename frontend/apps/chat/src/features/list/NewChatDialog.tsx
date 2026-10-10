import { Link2, NotebookPen, Users } from 'lucide-react'
import { useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'
import { parseAccountAddress, withHomeServer } from '@kutup/chat-core/identity'
import { inviteFragmentFromUrl } from '@kutup/chat-core/invite-links'
import { Button } from '@kutup/ui/components/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { Field } from '@kutup/ui/components/field'
import { offerAddToContacts } from '@kutup/contacts-core/addToContacts'
import { ContactSuggestInput } from '@kutup/contacts-core/ui/ContactSuggestInput'
import { useChat } from '../../app/chatStore'
import { openJoinLink } from '../../lib/joinLink'
import { NewGroupDialog } from './NewGroupDialog'
import { pathForAddress } from './paths'

/**
 * Start a conversation with `username` (someone on this server) or
 * `username@server` (anywhere), or open the note to self. Nothing is sent
 * until the first message: the conversation just opens.
 */
export function NewChatDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const chat = useChat()
  const [value, setValue] = useState('')
  const [error, setError] = useState<string | undefined>()
  const [group, setGroup] = useState(false)

  function close() {
    onOpenChange(false)
    setValue('')
    setError(undefined)
  }

  function start(event: FormEvent) {
    event.preventDefault()
    if (chat.capabilities?.mlsGroups && inviteFragmentFromUrl(value)) {
      close()
      openJoinLink(value.trim())
      return
    }
    const parsed = parseAccountAddress(value)
    if (!parsed) {
      setError(t('chat.errors.invalidAddress'))
      return
    }
    close()
    const address = withHomeServer(parsed, chat.capabilities?.serverName)
    void navigate(pathForAddress(address))
    if (address.server) {
      const text = `${address.username}@${address.server}`
      void offerAddToContacts(text, { message: t('contactSuggest.offer', { address: text }), action: t('contactSuggest.add') })
    }
  }

  return (
    <>
    <Dialog open={open} onOpenChange={(next) => (next ? onOpenChange(true) : close())}>
      <DialogContent className="sm:max-w-md">
        <form onSubmit={start} className="space-y-4">
          <DialogHeader>
            <DialogTitle>{t('chat.newChat.title')}</DialogTitle>
            <DialogDescription>{t('chat.newChat.description', { server: chat.capabilities?.serverName ?? '' })}</DialogDescription>
          </DialogHeader>
          <Field label={t('chat.newChat.address')} error={error}>
            {(props) => (
              <ContactSuggestInput
                {...props}
                autoFocus
                placeholder={t('chat.username')}
                value={value}
                onValueChange={(next) => {
                  setValue(next)
                  setError(undefined)
                }}
              />
            )}
          </Field>
          <DialogFooter className="gap-2 sm:justify-between">
            <span className="flex flex-wrap gap-1">
              <Button
                type="button"
                variant="ghost"
                onClick={() => {
                  close()
                  if (chat.self) void navigate(pathForAddress(chat.self.account))
                }}
              >
                <NotebookPen />
                {t('chat.noteToSelf')}
              </Button>
              {chat.capabilities?.mlsGroups ? (
                <Button
                  type="button"
                  variant="ghost"
                  onClick={() => {
                    close()
                    setGroup(true)
                  }}
                  data-testid="chat-create-group"
                >
                  <Users />
                  {t('chat.group.new')}
                </Button>
              ) : null}
              {chat.capabilities?.mlsGroups ? (
                <Button
                  type="button"
                  variant="ghost"
                  onClick={() => {
                    close()
                    openJoinLink('')
                  }}
                  data-testid="chat-join-with-link"
                >
                  <Link2 />
                  {t('chat.groupLink.joinWithLink')}
                </Button>
              ) : null}
            </span>
            <Button type="submit" disabled={!value.trim()}>
              {t('chat.start')}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
    <NewGroupDialog open={group} onOpenChange={setGroup} />
    </>
  )
}
