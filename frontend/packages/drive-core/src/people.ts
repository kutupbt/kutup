import { useQuery } from '@tanstack/react-query'
import { useEffect, useState } from 'react'
import axios from 'axios'
import { fromBase64, openProfileKeyEnvelope, sealProfileKeyEnvelope, toBase64 } from '@kutup/crypto'
import { accountRoute } from '@kutup/chat-core/transport'
import { loadChatWasm } from '@kutup/chat-core/wasm'
import type { ProfileLookup } from '@kutup/chat-core/types'
import { accountKeyOf, type AccountRef } from '@kutup/crypto/accountRef'
import api from '@kutup/session/client'
import { useDriveIdentity, type DriveIdentity } from './identity'

/**
 * Names and pictures for the people you share folders with
 * (docs/plans/unified-profile.md). Profiles are end-to-end encrypted: each
 * side hands the other its profile key, sealed to their Drive key and signed
 * with its own, and reads the other's profile with the key it got. Anyone
 * who has not given theirs yet (or whose key is out of date) shows as their
 * address.
 *
 * Profiles are kept by account (docs/plans/account-ids.md). The address the
 * server says each account has now is only an index for callers that hold
 * an address: as Signal's username lookup, it finds an account, and the
 * profile shown is that account's own.
 */

export interface PersonProfile {
  displayName: string
  /** Standard base64. */
  avatar?: string
  avatarContentType?: string
}

interface DrivePerson {
  /** Who: their server and permanent account id. */
  server: string
  accountId: string
  /** Shown only: their address now (server-asserted). */
  account: string
  local: boolean
  accountIncarnationId: string | null
  drivePublicKey: string | null
  driveSigningPublicKey: string | null
  receivedEnvelope: string | null
  sentProfileVersion: string | null
}

interface RemoteUser {
  server: string
  accountId: string
  accountIncarnationId: string
  driveHpkePublicKey: string
  driveSigningPublicKey: string
}

interface Keys {
  incarnationId: string
  hpkePublicKey: string
  signingPublicKey: string
}

/** Everyone you share with: profiles by account, and the address each has now. */
export interface People {
  /** By the account's string form, `aci:<uuid>@<server>`. */
  byAccount: Map<string, PersonProfile>
  /** The address each account has now, as its server says: a lookup index, never a key. */
  accountAt: Map<string, string>
}

export const peopleKey = ['drive-people'] as const

const remoteKeys = new Map<string, Promise<Keys | null>>()

function refOf(person: DrivePerson): AccountRef {
  return { server: person.server, accountId: person.accountId }
}

/** Someone's Drive keys: from this server, or looked up on theirs by account id (once a session). */
function keysOf(person: DrivePerson): Promise<Keys | null> {
  if (person.local) {
    return Promise.resolve(
      person.accountIncarnationId && person.drivePublicKey && person.driveSigningPublicKey
        ? {
            incarnationId: person.accountIncarnationId,
            hpkePublicKey: person.drivePublicKey,
            signingPublicKey: person.driveSigningPublicKey,
          }
        : null,
    )
  }
  const cacheKey = `${person.server}/${person.accountId}`
  let pending = remoteKeys.get(cacheKey)
  if (!pending) {
    pending = api
      .get<RemoteUser>(`/users/by-id/${encodeURIComponent(person.accountId)}`, {
        params: { server: person.server },
      })
      .then(({ data }) => {
        if (data.server !== person.server || data.accountId !== person.accountId) throw new Error('another account')
        return data
      })
      .then((data) => ({
        incarnationId: data.accountIncarnationId,
        hpkePublicKey: data.driveHpkePublicKey,
        signingPublicKey: data.driveSigningPublicKey,
      }))
      .catch(() => {
        remoteKeys.delete(cacheKey)
        return null
      })
    remoteKeys.set(cacheKey, pending)
  }
  return pending
}

/** Your own profile key; null before you have a profile. */
async function ownLookup(me: DriveIdentity): Promise<ProfileLookup | null> {
  let sealed: unknown
  try {
    sealed = (await api.get('/chat/profile')).data
  } catch (error) {
    if (axios.isAxiosError(error) && error.response?.status === 404) return null
    throw error
  }
  const wasm = await loadChatWasm()
  // Sealed for the account, never its address.
  return wasm.accountProfileKey(me.masterKey, sealed, accountKeyOf(me.accountRef), me.binding)
}

/** Give someone your current profile key, if they do not have it yet. */
async function give(person: DrivePerson, keys: Keys, own: ProfileLookup, me: DriveIdentity) {
  if (person.sentProfileVersion === own.version) return
  const envelope = await sealProfileKeyEnvelope(
    fromBase64(own.key),
    me.masterKey,
    keys.hpkePublicKey,
    {
      sender: me.accountRef,
      senderIncarnationId: me.incarnationId,
      recipient: refOf(person),
      recipientIncarnationId: keys.incarnationId,
    },
  )
  await api.put('/drive/profile-keys', {
    recipientServer: person.server,
    recipientAccountId: person.accountId,
    envelope,
    profileVersion: own.version,
  })
}

/** Their profile, with the key they gave you; null if it does not open or is gone. */
async function read(person: DrivePerson, keys: Keys, me: DriveIdentity): Promise<PersonProfile | null> {
  if (!person.receivedEnvelope) return null
  const key = await openProfileKeyEnvelope(person.receivedEnvelope, keys.signingPublicKey, me.privateKey, {
    sender: refOf(person),
    senderIncarnationId: keys.incarnationId,
    recipient: me.accountRef,
    recipientIncarnationId: me.incarnationId,
  })
  const wasm = await loadChatWasm()
  const lookup = wasm.profileLookup(toBase64(key))
  // The profile is the account's, sealed for it: fetched and opened by its key.
  const account = accountKeyOf(refOf(person))
  const { path, server } = accountRoute(account, `/profile/${encodeURIComponent(lookup.version)}`)
  const { data } = await api.get<unknown>(path, {
    params: { server },
    headers: { 'x-kutup-profile-access-key': lookup.accessKey },
  })
  const view = wasm.profileOpenPeer(account, data, lookup.key)
  if (!view.displayName && !view.avatar) return null
  return {
    displayName: view.displayName,
    ...(view.avatar ? { avatar: view.avatar, avatarContentType: view.avatarContentType } : {}),
  }
}

export async function loadPeople(me: DriveIdentity): Promise<People> {
  const { data } = await api.get<{ people: DrivePerson[] }>('/drive/people')
  const people: People = { byAccount: new Map(), accountAt: new Map() }
  for (const person of data.people) {
    try {
      people.accountAt.set(person.account.toLowerCase(), accountKeyOf(refOf(person)))
    } catch {
      // Not a canonical account: nobody to show for it.
    }
  }
  // Nobody to exchange with: the Chat runtime (megabytes of WASM) is not
  // needed at all (docs/research/18-web-performance.md).
  if (data.people.length === 0) return people
  const own = await ownLookup(me).catch(() => null)
  await Promise.all(
    data.people.map(async (person) => {
      const keys = await keysOf(person)
      if (!keys) return
      // Each half on its own: a failure leaves that person as their address
      // (or, for giving, retries on the next load).
      await Promise.all([
        own ? give(person, keys, own, me).catch(() => undefined) : undefined,
        read(person, keys, me).then(
          (profile) => profile && people.byAccount.set(accountKeyOf(refOf(person)), profile),
          () => undefined,
        ),
      ])
    }),
  )
  return people
}

/**
 * Everyone you share with, by account. Mounted by the shell so keys are
 * exchanged whenever Drive is open, and refreshed now and then for profile
 * changes.
 */
export function usePeople() {
  const identity = useDriveIdentity()
  const idle = useIdle()
  return useQuery({
    queryKey: [...peopleKey, identity.data?.accountRef.server, identity.data?.accountRef.accountId],
    // After the page's own first work: the exchange can load the Chat
    // runtime, which should not compete with the first listing.
    enabled: Boolean(identity.data) && idle,
    staleTime: 2 * 60_000,
    refetchInterval: 5 * 60_000,
    queryFn: () => loadPeople(identity.data!),
  })
}

/** True once the browser has been idle after the first render (at most 3 s later). */
function useIdle(): boolean {
  const [idle, setIdle] = useState(false)
  useEffect(() => {
    if (typeof window.requestIdleCallback === 'function') {
      const id = window.requestIdleCallback(() => setIdle(true), { timeout: 3000 })
      return () => window.cancelIdleCallback(id)
    }
    const id = window.setTimeout(() => setIdle(true), 1000)
    return () => window.clearTimeout(id)
  }, [])
  return idle
}

/**
 * How to show someone found by an address: the profile of the account that
 * address belongs to now, once it gave you its key, else the address.
 */
export function personOf(people: People | undefined, address: string): { name: string; profile: PersonProfile | null } {
  const key = people?.accountAt.get(address.toLowerCase())
  const profile = (key && people?.byAccount.get(key)) || null
  return { name: profile?.displayName || address, profile }
}

/** How to show an account: its profile once it gave you its key, else `fallback` (its address, when known). */
export function personOfAccount(
  people: People | undefined,
  account: AccountRef,
  fallback: string,
): { name: string; profile: PersonProfile | null } {
  let key: string
  try {
    key = accountKeyOf(account)
  } catch {
    return { name: fallback, profile: null }
  }
  const profile = people?.byAccount.get(key) ?? null
  return { name: profile?.displayName || fallback, profile }
}
