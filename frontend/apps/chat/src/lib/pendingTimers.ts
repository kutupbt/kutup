// A new direct chat is a message request until the other person accepts,
// and a conversation timer can only be set once it is accepted (docs/
// chat-protocol.md). So the default timer for new chats is owed: messages
// carry it themselves meanwhile, and the timer is set on acceptance. Kept
// per account by its id, never by its name (docs/plans/account-identity.md).

const PREFIX = 'kutup.chat.pendingTimers:'

function read(accountId: string): Record<string, number> {
  try {
    const parsed: unknown = JSON.parse(window.localStorage.getItem(PREFIX + accountId) ?? '{}')
    return parsed && typeof parsed === 'object' ? (parsed as Record<string, number>) : {}
  } catch {
    return {}
  }
}

function write(accountId: string, timers: Record<string, number>): void {
  try {
    if (Object.keys(timers).length === 0) window.localStorage.removeItem(PREFIX + accountId)
    else window.localStorage.setItem(PREFIX + accountId, JSON.stringify(timers))
  } catch {
    // Kept for this tab only: the messages still carry their expiry.
  }
}

export function pendingDefaultTimer(accountId: string, conversationKey: string): number | undefined {
  return read(accountId)[conversationKey]
}

export function owePendingDefaultTimer(accountId: string, conversationKey: string, seconds: number): void {
  write(accountId, { ...read(accountId), [conversationKey]: seconds })
}

export function settlePendingDefaultTimer(accountId: string, conversationKey: string): void {
  const timers = read(accountId)
  delete timers[conversationKey]
  write(accountId, timers)
}
