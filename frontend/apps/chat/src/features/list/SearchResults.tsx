import { SearchX } from 'lucide-react'
import { useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'
import { conversationKey } from '@kutup/chat-core/identity'
import { isVisibleChatMessage } from '@kutup/chat-core/disappearing'
import { searchChatHistory } from '@kutup/chat-core/search'
import { useChat } from '../../app/chatStore'
import { Avatar } from '../../components/Avatar'
import { conversationTitle, personName } from '../../lib/names'
import { formatShortTime } from '../../lib/time'
import { useNow } from '../../lib/useNow'
import { conversationList, foldMutations, messageIdOf } from '../../state/views'
import { conversationPath } from './paths'

/** Conversations whose name matches, then messages that do (newest first). */
export function SearchResults({ query }: { query: string }) {
  const { t, i18n } = useTranslation()
  const chat = useChat()
  const now = useNow(60_000)
  const self = chat.self!
  const { snapshot } = chat
  const profiles = useMemo(() => new Map(snapshot.profiles.map((p) => [p.peer, p])), [snapshot.profiles])

  const all = useMemo(() => conversationList(snapshot, self.address, now), [snapshot, self.address, now])
  const byKey = useMemo(() => new Map(all.map((c) => [c.key, c])), [all])
  const conversations = useMemo(() => {
    const needle = query.toLocaleLowerCase()
    return all.filter((item) => {
      const title = conversationTitle(item.conversation, item.address, item.profile, self.address, t, item.groupInfo)
      return title.toLocaleLowerCase().includes(needle) || (item.address ?? '').includes(needle)
    })
  }, [query, all, self.address, t])

  const messages = useMemo(() => {
    const visible = snapshot.history.filter((m) => isVisibleChatMessage(m, now))
    return searchChatHistory(visible, query, foldMutations(snapshot.history, self.address)).reverse()
  }, [query, snapshot.history, self.address, now])

  if (conversations.length === 0 && messages.length === 0) {
    return (
      <div className="flex flex-col items-center gap-3 px-8 pt-24 text-center text-sm text-muted-foreground">
        <SearchX className="size-8" aria-hidden />
        <p>{t('chat.search.noResults', { query })}</p>
      </div>
    )
  }

  const row = 'flex items-center gap-3 rounded-[10px] px-3 py-2 outline-none hover:bg-muted focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ring'
  return (
    <div className="px-2 py-2" data-testid="chat-search-results">
      {conversations.length > 0 ? (
        <section aria-labelledby="search-conversations">
          <h2 id="search-conversations" className="px-3 pb-1 pt-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
            {t('chat.search.conversations')}
          </h2>
          <ul>
            {conversations.map((item) => {
              const title = conversationTitle(item.conversation, item.address, item.profile, self.address, t, item.groupInfo)
              return (
                <li key={item.key}>
                  <Link to={conversationPath(item.key)} className={row}>
                    <Avatar name={title} image={item.groupInfo?.avatar?.data ?? item.profile?.avatar} contentType={item.groupInfo?.avatar?.contentType ?? item.profile?.avatarContentType} group={item.conversation.kind === 'group'} size={32} />
                    <span className="truncate text-sm font-medium">{title}</span>
                  </Link>
                </li>
              )
            })}
          </ul>
        </section>
      ) : null}
      {messages.length > 0 ? (
        <section aria-labelledby="search-messages" className="mt-2">
          <h2 id="search-messages" className="px-3 pb-1 pt-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
            {t('chat.search.messages')}
          </h2>
          <ul>
            {messages.map(({ message, preview }) => {
              const key = conversationKey(message.conversation)
              const summary = byKey.get(key)
              const title = summary
                ? conversationTitle(summary.conversation, summary.address, summary.profile, self.address, t, summary.groupInfo)
                : conversationTitle(message.conversation, null, null, self.address, t)
              const author = message.direction === 'outgoing' ? self.address : message.peer
              return (
                <li key={message.id}>
                  <Link
                    to={`${conversationPath(key)}?${new URLSearchParams({ focus: messageIdOf(message) }).toString()}`}
                    className={row}
                    data-testid="chat-search-result"
                  >
                    <span className="min-w-0 flex-1">
                      <span className="flex items-baseline gap-2">
                        <span className="min-w-0 flex-1 truncate text-sm font-semibold">{title}</span>
                        <span className="shrink-0 text-xs text-muted-foreground">
                          {formatShortTime(message.timestampMs, now, i18n.language, t)}
                        </span>
                      </span>
                      <span className="line-clamp-2 text-[0.8125rem] text-muted-foreground">
                        {message.conversation.kind === 'group' ? `${personName(author, profiles, self.address, t)}: ` : ''}
                        {preview}
                      </span>
                    </span>
                  </Link>
                </li>
              )
            })}
          </ul>
        </section>
      ) : null}
    </div>
  )
}
