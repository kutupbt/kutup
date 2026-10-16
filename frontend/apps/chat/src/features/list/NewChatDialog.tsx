import { Link2, NotebookPen, Users } from 'lucide-react'
import { useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'
import { inviteFragmentFromUrl } from '@kutup/chat-core/invite-links'
import { Button } from '@kutup/ui/components/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { Field } from '@kutup/ui/components/field'
import { ContactSuggestInput } from '@kutup/contacts-core/ui/ContactSuggestInput'
import { useChat } from '../../app/chatStore'
import { openJoinLink } from '../../lib/joinLink'
import { NewGroupDialog } from './NewGroupDialog'
import type { AccountRef } from '@kutup/chat-core/identity'
import { resolveTyped } from '../../lib/resolveAddress'
import { SomeoneElseNotice } from '../contacts/SomeoneElseNotice'
import { pathForAccount } from './paths'

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
  const [looking, setLooking] = useState(false)
  /** The address typed leads to someone else than the person known there: opened only on a second press. */
  const [warned, setWarned] = useState<{ value: string; account: AccountRef; text: string } | null>(null)

  function close() {
    onOpenChange(false)
    setValue('')
    setError(undefined)
    setWarned(null)
  }

  async function start(event: FormEvent) {
    event.preventDefault()
    if (looking) return
    if (chat.capabilities?.mlsGroups && inviteFragmentFromUrl(value)) {
      close()
      openJoinLink(value.trim())
      return
    }
    // The address leads to an account; the conversation is the account's.
    let account: AccountRef
    if (warned && warned.value === value) {
      account = warned.account
    } else {
      setLooking(true)
      const resolved = await resolveTyped(value, chat.capabilities?.serverName, t).finally(() => setLooking(false))
      if ('error' in resolved) {
        setError(resolved.error)
        return
      }
      if (resolved.warning) {
        setWarned({ value, account: resolved.account, text: resolved.warning })
        return
      }
      account = resolved.account
    }
    close()
    // Someone not in the address book is offered Save to contacts in the
    // conversation itself, where it stays until saved or dismissed.
    void navigate(pathForAccount(account))
  }

  return (
    <>
    <Dialog open={open} onOpenChange={(next) => (next ? onOpenChange(true) : close())}>
      <DialogContent className="sm:max-w-md">
        <form onSubmit={(event) => void start(event)} className="space-y-4">
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
                  setWarned(null)
                }}
              />
            )}
          </Field>
          {warned ? <SomeoneElseNotice text={warned.text} /> : null}
          <DialogFooter className="gap-2 sm:justify-between">
            <span className="flex flex-wrap gap-1">
              <Button
                type="button"
                variant="ghost"
                onClick={() => {
                  close()
                  if (chat.self) void navigate(pathForAccount(chat.self.account))
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
            <Button type="submit" disabled={!value.trim() || looking}>
              {warned ? t('chat.someoneElse.openAnyway') : t('chat.start')}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
    <NewGroupDialog open={group} onOpenChange={setGroup} />
    </>
  )
}
