import { foldAddress } from '@kutup/crypto/accountRename'
import { moveDraft } from '../lib/drafts'
import { moveReadMark } from './readState'

// Peers that renamed (docs/plans/username-renames.md): the Chat core moved
// their threads; this device's own per-conversation state (read marks,
// drafts) and an open thread follow. `aliases` is the core's log, folded
// old address → where the peer is now.

export type RenameAliases = Readonly<Record<string, string>>

/** The key a direct conversation goes by now, or null when its peer never moved. */
export async function currentKey(key: string, aliases: RenameAliases): Promise<string | null> {
  if (!key.startsWith('direct:')) return null
  const folded = await foldAddress(key.slice('direct:'.length))
  const now = folded ? aliases[folded] : undefined
  return now && `direct:${now}` !== key ? `direct:${now}` : null
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
