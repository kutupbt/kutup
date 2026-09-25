import { LockKeyhole } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { useParams, useSearchParams } from 'react-router-dom'
import { cn } from '@kutup/ui/lib/cn'
import { ConnectionBanner } from '../features/list/ConnectionBanner'
import { ConversationList } from '../features/list/ConversationList'
import { GroupInvitations } from '../features/list/GroupInvitations'
import { parseConversationKey } from '../features/list/paths'
import { SearchResults } from '../features/list/SearchResults'
import { ConversationView } from '../features/thread/ConversationView'

/**
 * The chat itself, Signal Desktop's two panes inside the Kutup frame: the
 * conversation list (or search results) on the left, the open conversation
 * on the right. On a phone, one at a time.
 */
export function ChatsPage() {
  const { t } = useTranslation()
  const { key } = useParams()
  const [params] = useSearchParams()
  const query = params.get('q')?.trim() ?? ''
  const selectedKey = key ?? null
  const conversation = selectedKey ? parseConversationKey(selectedKey) : null

  return (
    <div className="flex h-[calc(100svh-3.5rem)] min-h-0">
      <section
        aria-label={t('chat.list.label')}
        className={cn(
          'flex w-full min-w-0 flex-col border-r border-border md:w-80 md:shrink-0',
          conversation && 'hidden md:flex',
        )}
      >
        <ConnectionBanner />
        <div className="min-h-0 flex-1 overflow-y-auto">
          {query ? (
            <SearchResults query={query} />
          ) : (
            <>
              <GroupInvitations />
              <ConversationList selectedKey={conversation ? selectedKey : null} />
            </>
          )}
        </div>
      </section>
      <section className={cn('flex min-w-0 flex-1 flex-col', !conversation && 'hidden md:flex')}>
        {conversation ? (
          <>
            {/* On a phone the list, and its notice, is hidden behind the thread. */}
            <div className="md:hidden">
              <ConnectionBanner />
            </div>
            <div className="min-h-0 flex-1">
              <ConversationView key={selectedKey} conversation={conversation} />
            </div>
          </>
        ) : selectedKey ? (
          <p className="p-8 text-center text-sm text-muted-foreground">{t('chat.thread.notFound')}</p>
        ) : (
          <div className="flex h-full flex-col items-center justify-center gap-3 px-8 text-center">
            <LockKeyhole className="size-10 text-muted-foreground" aria-hidden />
            <p className="text-base font-medium">{t('chat.chooseConversation')}</p>
            <p className="max-w-sm text-sm text-muted-foreground">{t('chat.encryptedIntro')}</p>
          </div>
        )}
      </section>
    </div>
  )
}
