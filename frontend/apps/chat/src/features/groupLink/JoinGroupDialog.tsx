import { useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { Button } from '@kutup/ui/components/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { Field } from '@kutup/ui/components/field'
import { Input } from '@kutup/ui/components/input'
import { useChat } from '../../app/chatStore'
import { chatGroupLinkFragment, groupLinkFragmentFromUrl } from '../../lib/chatGroupLink'
import { closeJoinLink, openJoinLink, useJoinLink } from '../../lib/joinLink'
import { ChatGroupJoinDialog } from './ChatGroupJoinDialog'

/**
 * What a group link leads to, at the top of the app: the group and asking to
 * join (`ChatGroupJoinDialog`), or, opened without a link, a field to paste
 * one into.
 */
export function JoinGroupHost() {
  const url = useJoinLink()
  const { capabilities } = useChat()
  if (url === null || capabilities?.pairwiseGroups !== true) return null
  const fragment = url ? chatGroupLinkFragment(url) : null
  if (fragment) return <ChatGroupJoinDialog key={fragment} fragment={fragment} />
  return <PasteGroupLinkDialog key={url} invalid={url !== ''} />
}

/** Paste a group link someone shared; `invalid` when the one given isn't one. */
function PasteGroupLinkDialog({ invalid }: { invalid: boolean }) {
  const { t } = useTranslation()
  const [pasted, setPasted] = useState('')
  const [notALink, setNotALink] = useState(invalid)

  function submit(event: FormEvent) {
    event.preventDefault()
    // A link (`https://…/join#…`), or its fragment alone.
    const text = pasted.trim()
    const fragment = groupLinkFragmentFromUrl(text) ?? (text.includes('#') ? null : chatGroupLinkFragment(text))
    if (fragment) openJoinLink(fragment)
    else setNotALink(true)
  }

  return (
    <Dialog open onOpenChange={(open) => !open && closeJoinLink()}>
      <DialogContent className="sm:max-w-sm" data-testid="chat-join-dialog">
        <DialogHeader>
          <DialogTitle>{t('chat.groupLink.joinTitle')}</DialogTitle>
          <DialogDescription>{t('chat.groupLink.pasteHint')}</DialogDescription>
        </DialogHeader>
        <form onSubmit={submit} className="space-y-3">
          <Field
            label={t('chat.groupLink.pasteLabel')}
            error={notALink ? t('chat.groupLink.errors.invalid') : undefined}
          >
            {(props) => (
              <Input
                {...props}
                value={pasted}
                onChange={(e) => {
                  setPasted(e.target.value)
                  setNotALink(false)
                }}
                placeholder="https://…/join#…"
                autoCapitalize="none"
                autoCorrect="off"
                autoFocus
                data-testid="chat-join-paste"
              />
            )}
          </Field>
          <DialogFooter>
            <Button type="submit" disabled={!pasted.trim()}>{t('chat.groupLink.continue')}</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
