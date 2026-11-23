// Who gets which copy of a message, decided apart from the lookups that
// feed it (`sendDraft`): the same rules, and the same fixtures
// (crates/kutup-mail-client/tests/fixtures/send.json), as the Rust client
// core's `send` module, which the desktop bridge and the native apps use.

/** Proton's PGP schemes for outside recipients. */
export type Scheme = 'pgpMime' | 'inline'

/** What looking a recipient up as a Kutup address gave (`KutupLookup`). */
export type KutupLookup = { kind: 'keys'; encryptionDisabled: boolean } | { kind: 'disabled' } | { kind: 'notKutup' } | { kind: 'group' } | { kind: 'failed' }

/** Why a send can't go (`SendError`). */
export class SendPlanError extends Error {
  constructor(
    readonly error: 'pinnedKeyConflict' | 'recipientDisabled' | 'pinnedKeyUnusable' | 'unknownRecipient' | 'lookupFailed',
    readonly address: string,
  ) {
    super(`${error}: ${address}`)
  }
}

/** Every recipient once, lowercased, in the order given (To, Cc, Bcc). */
export function everyone(to: string[], cc: string[], bcc: string[]): string[] {
  return [...new Set([...to, ...cc, ...bcc].map((address) => address.toLowerCase()))]
}

/** The recipients split into Kutup ones and outside ones. */
export function splitRecipients(
  addresses: string[],
  onServer: (address: string) => boolean,
  lookup: (address: string) => KutupLookup,
  pinnedKeys: (address: string) => boolean,
): { local: string[]; external: string[] } {
  const local: string[] = []
  const external: string[] = []
  for (const address of addresses) {
    if (onServer(address)) {
      local.push(address)
      continue
    }
    const found = lookup(address)
    switch (found.kind) {
      case 'keys':
        // This server's word never outranks keys Contacts trust.
        if (pinnedKeys(address)) throw new SendPlanError('pinnedKeyConflict', address)
        local.push(address)
        break
      case 'disabled':
        throw new SendPlanError('recipientDisabled', address)
      case 'notKutup':
        external.push(address)
        break
      default:
        throw new SendPlanError('lookupFailed', address)
    }
  }
  return { local, external }
}

/** One PGP message for outside recipients. */
export interface PgpGroup {
  recipients: string[]
  keys: string[]
  inline: boolean
}

/**
 * The PGP messages for outside recipients (To and Cc together per scheme,
 * each Bcc on their own) and who gets the readable message. `keyOf` is the
 * recipient's OpenPGP key from its protection, `unusable` whether every key
 * Contacts trust for it is unusable.
 */
export function pgpGroups(
  external: string[],
  keyOf: (address: string) => string | null,
  unusable: (address: string) => boolean,
  bcc: string[],
  scheme: (address: string) => Scheme | undefined,
  defaultScheme: Scheme,
  encrypt: boolean,
): { groups: PgpGroup[]; plain: string[] } {
  const stuck = external.find(unusable)
  if (stuck) throw new SendPlanError('pinnedKeyUnusable', stuck)
  const blind = new Set(bcc.map((address) => address.toLowerCase()))
  const keyed = encrypt
    ? external.flatMap((address) => {
        const key = keyOf(address)
        return key ? [{ address, key, inline: (scheme(address) ?? defaultScheme) === 'inline' }] : []
      })
    : []
  const group = (members: typeof keyed): PgpGroup => ({ recipients: members.map((m) => m.address), keys: members.map((m) => m.key), inline: members[0]?.inline ?? false })
  const groups = [
    group(keyed.filter((r) => !blind.has(r.address) && !r.inline)),
    group(keyed.filter((r) => !blind.has(r.address) && r.inline)),
    ...keyed.filter((r) => blind.has(r.address)).map((r) => group([r])),
  ].filter((g) => g.recipients.length > 0)
  const plain = external.filter((address) => !keyed.some((r) => r.address === address))
  return { groups, plain }
}

/** A Kutup recipient's keys as the plan needs them. */
export interface PlanKeys {
  address: string
  primary: string
  encryptionDisabled: boolean
}

/** What a Kutup recipient's lookup gave at send time. */
export type KutupRecipient = { kind: 'keys'; keys: PlanKeys } | { kind: 'group'; members: PlanKeys[] } | { kind: 'notKutup' } | { kind: 'disabled' }

/**
 * The Kutup recipients' copies (each address, or each member of a group,
 * once, never the sender) and who gets the message readable: with Encrypt
 * off, or an address that forwards outside. A list's members stay end to
 * end whatever Encrypt says.
 */
export function kutupTargets(
  local: string[],
  lookup: (address: string) => KutupRecipient,
  sender: string,
  encrypt: boolean,
): { keyed: [string, string][]; readable: string[] } {
  const keyed: [string, string][] = []
  const readable: string[] = []
  const put = (address: string, keys: PlanKeys, encrypted: boolean) => {
    if (encrypted && !keys.encryptionDisabled) keyed.push([address, keys.primary])
    else readable.push(address)
  }
  for (const address of local) {
    const found = lookup(address)
    switch (found.kind) {
      case 'keys':
        put(address, found.keys, encrypt)
        break
      case 'group':
        for (const member of found.members) {
          if (member.address === sender || keyed.some(([a]) => a === member.address) || readable.includes(member.address)) continue
          put(member.address, member, true)
        }
        break
      case 'notKutup':
        throw new SendPlanError('unknownRecipient', address)
      case 'disabled':
        throw new SendPlanError('recipientDisabled', address)
    }
  }
  return { keyed, readable }
}
