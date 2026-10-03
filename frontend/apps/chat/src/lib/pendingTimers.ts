// A new direct chat is a message request until the other person accepts,
// and a conversation timer can only be set once it is accepted (docs/
// chat-protocol.md). So the default timer for new chats is owed: messages
// carry it themselves meanwhile, and the timer is set on acceptance.

const PREFIX = 'kutup.chat.pending-default-timers.v1:'

function read(account: string): Record<string, number> {
  try {
    const parsed: unknown = JSON.parse(window.localStorage.getItem(PREFIX + account) ?? '{}')
    return parsed && typeof parsed === 'object' ? (parsed as Record<string, number>) : {}
  } catch {
    return {}
  }
}

function write(account: string, timers: Record<string, number>): void {
  try {
    if (Object.keys(timers).length === 0) window.localStorage.removeItem(PREFIX + account)
    else window.localStorage.setItem(PREFIX + account, JSON.stringify(timers))
  } catch {
    // Kept for this tab only: the messages still carry their expiry.
  }
}

export function pendingDefaultTimer(account: string, conversationKey: string): number | undefined {
  return read(account)[conversationKey]
}

export function owePendingDefaultTimer(account: string, conversationKey: string, seconds: number): void {
  write(account, { ...read(account), [conversationKey]: seconds })
}

export function settlePendingDefaultTimer(account: string, conversationKey: string): void {
  const timers = read(account)
  delete timers[conversationKey]
  write(account, timers)
}
