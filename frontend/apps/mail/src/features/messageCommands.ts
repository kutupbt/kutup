// Message keys (Proton's R, Shift+R, Shift+F): the mailbox's keyboard
// handler asks, and the open conversation's newest message answers, since
// it holds the opened message a reply quotes.

export type ReplyKind = 'reply' | 'replyAll' | 'forward'

const EVENT = 'kutup-mail-reply'

/** Asks the open conversation's newest message to reply, reply to all, or forward. */
export function replyCommand(kind: ReplyKind) {
  window.dispatchEvent(new CustomEvent<ReplyKind>(EVENT, { detail: kind }))
}

/** Listens for {@link replyCommand}; returns the unsubscribe. */
export function onReplyCommand(listener: (kind: ReplyKind) => void): () => void {
  const handle = (event: Event) => listener((event as CustomEvent<ReplyKind>).detail)
  window.addEventListener(EVENT, handle)
  return () => window.removeEventListener(EVENT, handle)
}
