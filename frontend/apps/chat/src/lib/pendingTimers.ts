// A new direct chat is a message request until the other person accepts,
// and a conversation timer can only be set once it is accepted (docs/
// chat-protocol.md). So the default timer for new chats is owed: messages
// carry it themselves meanwhile, and the timer is set on acceptance. Kept
// per account by its id, never by its name (docs/plans/account-identity.md).

const PREFIX = 'kutup.chat.pending-default-timers.v2:'

function read(userId: string): Record<string, number> {
  try {
    const parsed: unknown = JSON.parse(window.localStorage.getItem(PREFIX + userId) ?? '{}')
    return parsed && typeof parsed === 'object' ? (parsed as Record<string, number>) : {}
  } catch {
    return {}
  }
}

function write(userId: string, timers: Record<string, number>): void {
  try {
    if (Object.keys(timers).length === 0) window.localStorage.removeItem(PREFIX + userId)
    else window.localStorage.setItem(PREFIX + userId, JSON.stringify(timers))
  } catch {
    // Kept for this tab only: the messages still carry their expiry.
  }
}

export function pendingDefaultTimer(userId: string, conversationKey: string): number | undefined {
  return read(userId)[conversationKey]
}

export function owePendingDefaultTimer(userId: string, conversationKey: string, seconds: number): void {
  write(userId, { ...read(userId), [conversationKey]: seconds })
}

export function settlePendingDefaultTimer(userId: string, conversationKey: string): void {
  const timers = read(userId)
  delete timers[conversationKey]
  write(userId, timers)
}
