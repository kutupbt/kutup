import { useCallback, useEffect, useState } from 'react'
import { accountHead, type AccountHeadClient, type HeadCondition } from './accountHead'
import { getSession, useSession } from './store'

/** What an app shell's HeadStateBanner shows: blocked, a notice, or nothing. */
export type HeadBannerState = { kind: 'blocked'; reason: 'rollback' | 'fork' } | { kind: 'tooOld' } | null

function bannerOf(condition: HeadCondition): HeadBannerState {
  if (condition.kind === 'blocked') return { kind: 'blocked', reason: condition.reason }
  if (condition.kind === 'trusted' && condition.notice === 'tooOld') return { kind: 'tooOld' }
  return null
}

/**
 * The account head's state for this app's shell (docs/plans/rollback-protection.md):
 * the head is checked once when the app opens, so a rolled-back or forked
 * history shows at once, not only at the next listed read; then whatever any
 * read or write in the app finds. Props for `HeadStateBanner`.
 */
export function useAccountHeadState(): {
  state: HeadBannerState
  onContinue: () => Promise<void>
  onDismiss: () => void
} {
  const session = useSession()
  // The account, not every change to the session (a quota, a colour).
  const account = session ? `${session.userId}:${session.envelopeBinding}` : null
  const [client, setClient] = useState<AccountHeadClient | null>(null)
  const [state, setState] = useState<HeadBannerState>(null)

  useEffect(() => {
    const session = getSession()
    if (!account || !session) {
      setClient(null)
      setState(null)
      return
    }
    let gone = false
    let unsubscribe: (() => void) | null = null
    void accountHead(session).then(
      (opened) => {
        if (gone) return
        setClient(opened)
        unsubscribe = opened.subscribe((condition) => setState(bannerOf(condition)))
        // A blocked head throws here and shows through the subscription; an
        // unreachable server is the app's own reads' business.
        opened.verifiedHead().catch(() => undefined)
      },
      () => undefined,
    )
    return () => {
      gone = true
      unsubscribe?.()
    }
  }, [account])

  const onContinue = useCallback(async () => {
    if (client) await client.continueWithServer()
  }, [client])
  const onDismiss = useCallback(() => client?.dismissNotice(), [client])
  return { state, onContinue, onDismiss }
}
