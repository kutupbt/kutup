import { Archive, ArchiveRestore, Bell, BellOff, MessageSquareDot, MessageSquareText, Pin, PinOff, Trash2 } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import type { ChatHistoryEntry, ConversationId } from '@kutup/chat-core/types'
import { isMuted } from '../../state/accountState'
import { type MenuParts } from './menuParts'
import { MUTE_PRESETS, useListActions } from './useListActions'

/**
 * Signal's conversation menu, the same from the list's "⋯", a right click
 * and the thread header: pin, mark read/unread, mute, archive, delete.
 */
export function ConversationMenuItems({
  parts,
  conversation,
  last,
  unread,
  onDelete,
  onMarkUnread,
}: {
  parts: MenuParts
  conversation: ConversationId
  last: ChatHistoryEntry | null
  unread: boolean
  onDelete: () => void
  /** After marking unread (the list leaves the conversation, so it stays unread). */
  onMarkUnread?: () => void
}) {
  const { t } = useTranslation()
  const actions = useListActions()
  const state = actions.state(conversation)
  const now = Date.now()
  const muted = isMuted(state, now)
  const archived = actions.isArchived(conversation, last, now)
  const { Item, Separator, Sub, SubTrigger, SubContent } = parts

  return (
    <>
      <Item onSelect={() => void actions.pin(conversation, !state?.pinned)} data-testid="chat-menu-pin">
        {state?.pinned ? <PinOff /> : <Pin />}
        {state?.pinned ? t('chat.list.unpin') : t('chat.list.pin')}
      </Item>
      {unread ? (
        <Item onSelect={() => void actions.markRead(conversation)} data-testid="chat-menu-read">
          <MessageSquareText />
          {t('chat.list.markRead')}
        </Item>
      ) : (
        <Item
          onSelect={() => {
            void actions.markUnread(conversation)
            onMarkUnread?.()
          }}
          data-testid="chat-menu-unread"
        >
          <MessageSquareDot />
          {t('chat.list.markUnread')}
        </Item>
      )}
      {muted ? (
        <Item onSelect={() => void actions.unmute(conversation)} data-testid="chat-menu-unmute">
          <Bell />
          {t('chat.list.unmute')}
        </Item>
      ) : (
        <Sub>
          <SubTrigger data-testid="chat-menu-mute">
            <BellOff />
            {t('chat.list.mute')}
          </SubTrigger>
          <SubContent>
            {MUTE_PRESETS.map((preset) => (
              <Item key={preset.id} onSelect={() => void actions.mute(conversation, preset.id)} data-testid={`chat-mute-${preset.id}`}>
                {t(`chat.list.mutePresets.${preset.id}`)}
              </Item>
            ))}
          </SubContent>
        </Sub>
      )}
      <Item onSelect={() => void actions.archive(conversation, !archived)} data-testid="chat-menu-archive">
        {archived ? <ArchiveRestore /> : <Archive />}
        {archived ? t('chat.list.unarchive') : t('chat.list.archive')}
      </Item>
      <Separator />
      <Item destructive onSelect={onDelete} data-testid="chat-menu-delete">
        <Trash2 />
        {t('chat.list.delete')}
      </Item>
    </>
  )
}
