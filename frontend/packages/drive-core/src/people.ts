import { useQuery } from '@tanstack/react-query'
import { useEffect, useState } from 'react'
import axios from 'axios'
import { fromBase64, openProfileKeyEnvelope, sealProfileKeyEnvelope, toBase64 } from '@kutup/crypto'
import { loadChatWasm } from '@kutup/chat-core/wasm'
import type { ProfileLookup } from '@kutup/chat-core/types'
import api from '@kutup/session/client'
import { useDriveIdentity, type DriveIdentity } from './identity'

/**
 * Names and pictures for the people you share folders with
 * (docs/plans/unified-profile.md). Profiles are end-to-end encrypted: each
 * side hands the other its profile key, sealed to their Drive key and signed
 * with its own, and reads the other's profile with the key it got. Anyone
 * who has not given theirs yet (or whose key is out of date) shows as their
 * address.
 */

export interface PersonProfile {
  displayName: string
  /** Standard base64. */
  avatar?: string
  avatarContentType?: string
}

interface DrivePerson {
  account: string
  local: boolean
  accountIncarnationId: string | null
  drivePublicKey: string | null
  driveSigningPublicKey: string | null
  receivedEnvelope: string | null
  sentProfileVersion: string | null
}

interface RemoteUser {
  accountIncarnationId: string
  driveHpkePublicKey: string
  driveSigningPublicKey: string
}

interface Keys {
  incarnationId: string
  hpkePublicKey: string
  signingPublicKey: string
}

export const peopleKey = ['drive-people'] as const

const remoteKeys = new Map<string, Promise<Keys | null>>()

/** Someone's Drive keys: from this server, or looked up on theirs (once a session). */
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
  let pending = remoteKeys.get(person.account)
  if (!pending) {
    const at = person.account.lastIndexOf('@')
    pending = api
      .get<RemoteUser>(`/drive/federation/users/${encodeURIComponent(person.account.slice(0, at))}`, {
        params: { server: person.account.slice(at + 1) },
      })
      .then(({ data }) => ({
        incarnationId: data.accountIncarnationId,
        hpkePublicKey: data.driveHpkePublicKey,
        signingPublicKey: data.driveSigningPublicKey,
      }))
      .catch(() => {
        remoteKeys.delete(person.account)
        return null
      })
    remoteKeys.set(person.account, pending)
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
  return wasm.accountProfileKey(me.masterKey, sealed, me.account)
}

/** Give someone your current profile key, if they do not have it yet. */
async function give(person: DrivePerson, keys: Keys, own: ProfileLookup, me: DriveIdentity) {
  if (person.sentProfileVersion === own.version) return
  const envelope = await sealProfileKeyEnvelope(
    fromBase64(own.key),
    me.masterKey,
    keys.hpkePublicKey,
    {
      senderAccount: me.account,
      senderIncarnationId: me.incarnationId,
      recipientAccount: person.account,
      recipientIncarnationId: keys.incarnationId,
    },
  )
  await api.put('/drive/profile-keys', {
    recipientAccount: person.account,
    envelope,
    profileVersion: own.version,
  })
}

/** Their profile, with the key they gave you; null if it does not open or is gone. */
async function read(person: DrivePerson, keys: Keys, me: DriveIdentity): Promise<PersonProfile | null> {
  if (!person.receivedEnvelope) return null
  const key = await openProfileKeyEnvelope(person.receivedEnvelope, keys.signingPublicKey, me.privateKey, {
    senderAccount: person.account,
    senderIncarnationId: keys.incarnationId,
    recipientAccount: me.account,
    recipientIncarnationId: me.incarnationId,
  })
  const wasm = await loadChatWasm()
  const lookup = wasm.profileLookup(toBase64(key))
  const { data } = await api.get<unknown>(
    `/chat/users/${encodeURIComponent(person.account)}/profile/${lookup.version}`,
    { headers: { 'x-kutup-profile-access-key': lookup.accessKey } },
  )
  const view = wasm.profileOpenPeer(person.account, data, lookup.key)
  if (!view.displayName && !view.avatar) return null
  return {
    displayName: view.displayName,
    ...(view.avatar ? { avatar: view.avatar, avatarContentType: view.avatarContentType } : {}),
  }
}

async function loadPeople(me: DriveIdentity): Promise<Map<string, PersonProfile>> {
  const { data } = await api.get<{ people: DrivePerson[] }>('/drive/people')
  const profiles = new Map<string, PersonProfile>()
  // Nobody to exchange with: the Chat runtime (megabytes of WASM) is not
  // needed at all (docs/research/17-web-performance.md).
  if (data.people.length === 0) return profiles
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
          (profile) => profile && profiles.set(person.account, profile),
          () => undefined,
        ),
      ])
    }),
  )
  return profiles
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
    queryKey: [...peopleKey, identity.data?.account],
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

/** How to show someone: their name and picture once they gave you their key, else their address. */
export function personOf(
  people: Map<string, PersonProfile> | undefined,
  account: string,
): { name: string; profile: PersonProfile | null } {
  const profile = people?.get(account) ?? null
  return { name: profile?.displayName || account, profile }
}
