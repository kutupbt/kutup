import type { ChatRenameAliases } from '@kutup/chat-core/types'
import { foldAddress } from '@kutup/crypto/accountRename'
import { moveDraft } from '../lib/drafts'
import { moveReadMark } from './readState'

// Peers that renamed (docs/plans/username-renames.md): the Chat core moved
// their threads; this device's own per-conversation state (read marks,
// drafts) and an open thread follow. `aliases` is the core's log, folded
// old address → where the peer is now. A name someone else took since is
// theirs: it no longer leads to the peer that left it.

export type RenameAliases = ChatRenameAliases

/** A digest of the log: what tells the app it changed (a rename back keeps its size). */
export function aliasesDigest(aliases: RenameAliases): string {
  return JSON.stringify(Object.entries(aliases).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)))
}

/** The key a direct conversation goes by now, or null when its peer never moved. */
export async function currentKey(key: string, aliases: RenameAliases): Promise<string | null> {
  if (!key.startsWith('direct:')) return null
  const folded = await foldAddress(key.slice('direct:'.length))
  const alias = folded ? aliases[folded] : undefined
  if (!alias || alias.reusedAtMs !== undefined) return null
  return `direct:${alias.to}` !== key ? `direct:${alias.to}` : null
}

/** Moves the read marks and drafts kept under `keys` to where their peers are now. */
export async function followRenamedState(keys: Iterable<string>, aliases: RenameAliases): Promise<void> {
  if (Object.keys(aliases).length === 0) return
  for (const key of new Set(keys)) {
    const now = await currentKey(key, aliases)
    if (!now) continue
    moveReadMark(key, now)
    moveDraft(key, now)
  }
}
