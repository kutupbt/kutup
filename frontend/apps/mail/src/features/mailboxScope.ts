import { useMemo } from 'react'
import { useParams } from 'react-router-dom'
import type { GroupScope, MailAccount } from '@kutup/mail-core/api'
import { heldKeys, useGroupKeys } from '@kutup/mail-core/groups'

/**
 * Which mailbox a route is in (docs/plans/mail-groups.md): the account's own
 * (`/inbox`) or a shared mailbox (`/g/{groupId}/inbox`).
 */
export interface MailboxScope {
  /** The shared mailbox's group id. */
  group?: string
  /** Prefix for links inside the mailbox. */
  base: string
}

export function useMailboxScope(): MailboxScope {
  const { groupId } = useParams()
  return useMemo(() => (groupId ? { group: groupId, base: `/g/${groupId}` } : { base: '' }), [groupId])
}

/**
 * The group keys the reader holds for the shared mailbox the route is in:
 * `undefined` in the account's own mailbox, `null` while they load.
 */
export function useGroupScope(account: MailAccount | undefined): GroupScope | null | undefined {
  const { group } = useMailboxScope()
  const keys = useGroupKeys(group)
  return useMemo(() => {
    if (!group) return undefined
    if (!keys.data || !account) return null
    return { groupId: group, keys: heldKeys(keys.data, [account.key, ...account.olderKeys]) }
  }, [group, keys.data, account])
}
