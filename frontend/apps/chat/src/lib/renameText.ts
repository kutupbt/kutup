import type { TFunction } from 'i18next'
import type { ChatPeerRenamed } from '@kutup/chat-core/types'

/** The username of `user@server`. */
function usernameOf(address: string): string {
  const at = address.lastIndexOf('@')
  return at > 0 ? address.slice(0, at) : address
}

/**
 * The line a followed rename leaves in its thread
 * (docs/plans/username-renames.md): "ada_l changed their username to
 * ada_lovelace". Usernames only: the server stays the same.
 */
export function renameText(renamed: ChatPeerRenamed, t: TFunction): string {
  return t('chat.renamed.line', { from: usernameOf(renamed.from), to: usernameOf(renamed.to) })
}
