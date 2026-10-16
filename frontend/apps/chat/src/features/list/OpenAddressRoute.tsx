import { Loader2 } from 'lucide-react'
import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Link, Navigate, useLocation, useParams } from 'react-router-dom'
import type { AccountRef } from '@kutup/chat-core/identity'
import { Button } from '@kutup/ui/components/button'
import { useChat } from '../../app/chatStore'
import { resolveTyped } from '../../lib/resolveAddress'
import { SomeoneElseNotice } from '../contacts/SomeoneElseNotice'
import { pathForAccount } from './paths'

type Lookup =
  | { kind: 'looking' }
  | { kind: 'open'; account: AccountRef }
  | { kind: 'warned'; account: AccountRef; text: string }
  | { kind: 'failed'; text: string }

/**
 * `/to/<address>[?call=audio]`: another app (Mail's person card) opens a chat
 * with someone by their address. The address is looked up and checked as a
 * typed one is (`resolveTyped`), then the account's conversation opens with
 * the same query; an address that leads to someone else than the person
 * known there opens only on "Open anyway".
 */
export function OpenAddressRoute() {
  const { t } = useTranslation()
  const { address = '' } = useParams()
  const { search } = useLocation()
  const { capabilities } = useChat()
  const [lookup, setLookup] = useState<Lookup>({ kind: 'looking' })
  const home = capabilities?.serverName ?? undefined

  useEffect(() => {
    let current = true
    setLookup({ kind: 'looking' })
    void resolveTyped(address, home, t).then((found) => {
      if (!current) return
      if ('error' in found) setLookup({ kind: 'failed', text: found.error })
      else if (found.warning) setLookup({ kind: 'warned', account: found.account, text: found.warning })
      else setLookup({ kind: 'open', account: found.account })
    })
    return () => {
      current = false
    }
  }, [address, home, t])

  if (lookup.kind === 'open') return <Navigate to={`${pathForAccount(lookup.account)}${search}`} replace />
  return (
    <main className="flex h-[calc(100svh-3.5rem)] flex-col items-center justify-center gap-4 px-6 text-center" data-testid="chat-open-address">
      {lookup.kind === 'looking' ? (
        <p className="flex items-center gap-2 text-sm text-muted-foreground" role="status">
          <Loader2 className="size-4 animate-spin" aria-hidden />
          {t('chat.openAddress.looking', { address })}
        </p>
      ) : lookup.kind === 'failed' ? (
        <>
          <p className="max-w-md text-sm" role="alert">{lookup.text}</p>
          <Button asChild variant="outline">
            <Link to="/">{t('chat.openAddress.back')}</Link>
          </Button>
        </>
      ) : (
        <div className="flex max-w-md flex-col items-stretch gap-3">
          <SomeoneElseNotice text={lookup.text} />
          <div className="flex justify-end gap-2">
            <Button asChild variant="ghost">
              <Link to="/">{t('common.cancel')}</Link>
            </Button>
            <Button asChild>
              <Link to={`${pathForAccount(lookup.account)}${search}`} replace>
                {t('chat.someoneElse.openAnyway')}
              </Link>
            </Button>
          </div>
        </div>
      )}
    </main>
  )
}
