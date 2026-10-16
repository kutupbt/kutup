import { isAxiosError } from 'axios'
import type { TFunction } from 'i18next'
import {
  addressString,
  isAccount,
  parseAddress,
  parseAddressInput,
  type AccountRef,
  type TypedAddress,
} from '@kutup/chat-core/identity'
import { recipientError, RecipientRenamed } from '@kutup/drive-core/identityPins'
import api from '@kutup/session/client'
import { driveIdentity } from '../state/accountNames'

// An address leads to an account (docs/plans/account-ids.md): as Signal's
// username lookup, the server's answer is a handle, never kept as who
// someone is. Chat opens the account's conversation; the engine then
// checks the account's signed keys and pins before anything is sent.

export type ResolvedAddress =
  | { kind: 'found'; account: AccountRef }
  | { kind: 'notFound' }
  /** A name its person left during its hold: they are `now` there (a verified rename chain says so). */
  | { kind: 'renamed'; now: string }
  | { kind: 'failed' }

/** The account `address` leads to, here or on another server. */
export async function resolveAddress(address: TypedAddress): Promise<ResolvedAddress> {
  const text = addressString(address)
  try {
    const { data } = await api.get<{ server: string; accountId: string }>(`/users/by-address/${encodeURIComponent(text)}`)
    const account = { server: data.server, accountId: data.accountId }
    // An account lives on the server of its address.
    if (account.server !== address.server || !isAccount(account)) return { kind: 'failed' }
    return { kind: 'found', account }
  } catch (error) {
    if (isAxiosError(error) && error.response?.status === 404) return { kind: 'notFound' }
    const me = driveIdentity()
    const known = me ? await recipientError(await me, text, error).catch((other: unknown) => other) : error
    if (known instanceof RecipientRenamed) return { kind: 'renamed', now: known.now }
    return { kind: 'failed' }
  }
}

/**
 * What a person typed (an address, a contact link, or a bare username on
 * `homeServer`) to the account it leads to, or the message to show.
 */
export async function resolveTyped(
  value: string,
  homeServer: string | undefined,
  t: TFunction,
): Promise<{ account: AccountRef } | { error: string }> {
  const address = homeServer ? parseAddressInput(value, homeServer) : parseAddress(value)
  if (!address) return { error: t('chat.errors.invalidAddress') }
  const resolved = await resolveAddress(address)
  switch (resolved.kind) {
    case 'found':
      return { account: resolved.account }
    case 'notFound':
      return { error: t('chat.errors.notFound') }
    case 'renamed':
      return { error: t('chat.errors.renamed', { address: addressString(address), now: resolved.now }) }
    case 'failed':
      return { error: t('chat.errors.lookupFailed') }
  }
}
