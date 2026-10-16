import type { TFunction } from 'i18next'
import {
  addressString,
  isAccount,
  parseAddress,
  parseAddressInput,
  type AccountRef,
  type TypedAddress,
} from '@kutup/chat-core/identity'
import { checkAnswer, lookupAddress, RecipientRenamed } from '@kutup/drive-core/identityPins'
import { distrustAddress, driveIdentity } from '../state/accountNames'

// An address leads to an account (docs/plans/account-ids.md): as Signal's
// username lookup, the server's answer is a handle, never kept as who
// someone is. The answer is checked against the account's identity pins by
// the address as typed: an address someone the user knows holds that leads
// to anyone else is told (`someoneElse`), and the account is shown by its
// own name, never the typed one. Chat opens that account's conversation;
// the engine then checks its signed keys and pins before anything is sent.

/** The address belongs to someone the list knows, and leads to another account. */
export interface SomeoneElse {
  /** Where the person the user knew there is now, when they moved on. */
  now?: string
  /** The own name of the account found, when the user knows it. */
  name?: string
}

export type ResolvedAddress =
  | { kind: 'found'; account: AccountRef; someoneElse?: SomeoneElse }
  | { kind: 'notFound' }
  /** A name its person left during its hold: they are `now` there (a verified rename chain says so). */
  | { kind: 'renamed'; now: string }
  | { kind: 'failed' }

/** The account `address` leads to, here or on another server. */
export async function resolveAddress(address: TypedAddress): Promise<ResolvedAddress> {
  const text = addressString(address)
  const me = driveIdentity()
  if (!me) return { kind: 'failed' }
  try {
    const identity = await me
    const answer = await lookupAddress(identity, text)
    if (!answer) return { kind: 'notFound' }
    const account = { server: answer.server, accountId: answer.accountId }
    // An account lives on the server of its address.
    if (account.server !== address.server || !isAccount(account)) return { kind: 'failed' }
    const status = await checkAnswer(identity, text, answer)
    if (status.kind !== 'someoneElse') return { kind: 'found', account }
    // Never named by the address it was found at.
    distrustAddress(account, text)
    return {
      kind: 'found',
      account,
      someoneElse: { ...(status.now ? { now: status.now } : {}), ...(status.name ? { name: status.name } : {}) },
    }
  } catch (error) {
    if (error instanceof RecipientRenamed) return { kind: 'renamed', now: error.now }
    return { kind: 'failed' }
  }
}

/** The notice for an address that leads to someone else than the person the user knew there (en/tr, shared). */
export function someoneElseNotice(address: string, found: SomeoneElse, t: TFunction): string {
  const body = found.now
    ? t('identityCheck.someoneElse.bodyNow', { account: address, now: found.now })
    : t('identityCheck.someoneElse.body', { account: address })
  return found.name ? `${body} ${t('chat.someoneElse.knownAs', { name: found.name })}` : body
}

/**
 * What a person typed (an address, a contact link, or a bare username on
 * `homeServer`) to the account it leads to, or the message to show. An
 * address that leads to someone else than the person known there comes
 * with its `warning`: the caller opens it only once the user goes on.
 */
export async function resolveTyped(
  value: string,
  homeServer: string | undefined,
  t: TFunction,
): Promise<{ account: AccountRef; warning?: string } | { error: string }> {
  const address = homeServer ? parseAddressInput(value, homeServer) : parseAddress(value)
  if (!address) return { error: t('chat.errors.invalidAddress') }
  const resolved = await resolveAddress(address)
  switch (resolved.kind) {
    case 'found':
      return resolved.someoneElse
        ? { account: resolved.account, warning: someoneElseNotice(addressString(address), resolved.someoneElse, t) }
        : { account: resolved.account }
    case 'notFound':
      return { error: t('chat.errors.notFound') }
    case 'renamed':
      return { error: t('chat.errors.renamed', { address: addressString(address), now: resolved.now }) }
    case 'failed':
      return { error: t('chat.errors.lookupFailed') }
  }
}
