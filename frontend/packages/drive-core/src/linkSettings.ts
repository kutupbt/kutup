// A public link's settings, as Proton Drive's link settings dialog
// (docs/plans/drive-link-password.md): its expiry and its password. Used for
// folder links (Drive), album links (Photos) and file links (Drive, Office,
// Maps).
//
// The URL fragment holds the link's secret. Without a password the secret is
// the link key the target is sealed under. Setting a password picks a new
// link key, re-seals the target's key under it and seals that link key under
// a key the secret and the password derive; the URL stays the same.
// Removing the password puts the target back under the secret.

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { generateKey, sealPublicLinkCollectionKeyV1, sealPublicLinkFileKeyV1 } from '@kutup/crypto'
import {
  openOwnerLinkKeyV1,
  openOwnerLinkSecretV1,
  protectLinkPasswordV1,
  sealOwnerLinkKeyV1,
  sealOwnerLinkSecretV1,
} from '@kutup/crypto/publicLink'
import api from '@kutup/session/client'
import { useDriveIdentity, type DriveIdentity } from './identity'

/** What a link's settings need of it: its owner's listing (folder or file access). */
export interface LinkSettingsLink {
  id: string
  token: string
  ownerLinkKeyEnvelope: string
  /** The link key's revision: a change starts from it. */
  keyRevision: number
  /** A protected link's secret and password for the owner. */
  ownerSecretEnvelope?: string
  expiresAt: string | null
}

/** What the link opens, with its key now: a folder (or album) at its epoch, or a file at its generation. */
export type LinkTarget =
  | { kind: 'collection'; id: string; key: Uint8Array; epoch: number }
  | { kind: 'file'; id: string; key: Uint8Array; generation: number }

/** The link's URL secret: what its fragment carries. */
export async function linkSecret(link: LinkSettingsLink, me: DriveIdentity): Promise<Uint8Array> {
  const context = { linkId: link.id, ownerAccountId: me.accountId }
  if (link.ownerSecretEnvelope) return (await openOwnerLinkSecretV1(link.ownerSecretEnvelope, me.roots, context)).secret
  return openOwnerLinkKeyV1(link.ownerLinkKeyEnvelope, me.roots, context)
}

/** A protected link's password, for its owner to see; '' when it has none. */
export async function linkPassword(link: LinkSettingsLink, me: DriveIdentity): Promise<string> {
  if (!link.ownerSecretEnvelope) return ''
  return (await openOwnerLinkSecretV1(link.ownerSecretEnvelope, me.roots, { linkId: link.id, ownerAccountId: me.accountId })).password
}

/** The link changed since it was read (another device, a folder re-key): reload and try again. */
export class LinkChanged extends Error {
  constructor() {
    super('the link changed')
  }
}

/** Sets (a password) or removes (null) a link's password. */
export async function setLinkPassword(
  link: LinkSettingsLink,
  target: LinkTarget,
  password: string | null,
  me: DriveIdentity,
): Promise<void> {
  const secret = await linkSecret(link, me)
  const nextRevision = link.keyRevision + 1
  // A new key for a password; the secret itself without one.
  const linkKey = password ? await generateKey() : secret
  const owner = { linkId: link.id, ownerAccountId: me.accountId }
  const targetKeyEnvelope =
    target.kind === 'collection'
      ? await sealPublicLinkCollectionKeyV1(target.key, linkKey, { collectionId: target.id, ownerAccountId: me.accountId, epoch: target.epoch })
      : await sealPublicLinkFileKeyV1(target.key, linkKey, { fileId: target.id, ownerAccountId: me.accountId, generation: target.generation })
  const protection = password
    ? {
        ...(await protectLinkPasswordV1(secret, password, linkKey, { ...owner, keyRevision: nextRevision })),
        ownerSecretEnvelope: await sealOwnerLinkSecretV1(secret, password, me.roots, owner),
      }
    : null
  try {
    await api.put(`/drive/public-links/${encodeURIComponent(link.token)}/password`, {
      fromKeyRevision: link.keyRevision,
      keyEpoch: target.kind === 'collection' ? target.epoch : target.generation,
      targetKeyEnvelope,
      ownerLinkKeyEnvelope: await sealOwnerLinkKeyV1(linkKey, me.roots, owner),
      password: protection,
    })
  } catch (error) {
    if ((error as { response?: { status?: number } }).response?.status === 409) throw new LinkChanged()
    throw error
  }
}

/** Sets when a link stops opening, or never (null). */
export async function setLinkExpiry(link: Pick<LinkSettingsLink, 'token'>, expiresAt: Date | null): Promise<void> {
  await api.put(`/drive/public-links/${encodeURIComponent(link.token)}/expiry`, {
    expiresAt: expiresAt ? expiresAt.toISOString() : null,
  })
}

export interface LinkSettingsChange {
  link: LinkSettingsLink
  target: LinkTarget
  /** The new password ('' removes it); undefined leaves it. */
  password?: string
  /** The new expiry (null: never); undefined leaves it. */
  expiresAt?: Date | null
}

/** Saves a link's settings dialog: expiry first, then the password. */
export function useSaveLinkSettings() {
  const queryClient = useQueryClient()
  const identity = useDriveIdentity()
  return useMutation({
    mutationFn: async (change: LinkSettingsChange) => {
      const me = identity.data
      if (!me) throw new Error('drive identity is not ready')
      if (change.expiresAt !== undefined) await setLinkExpiry(change.link, change.expiresAt)
      if (change.password !== undefined) await setLinkPassword(change.link, change.target, change.password || null, me)
    },
    onSettled: () =>
      Promise.all([
        queryClient.invalidateQueries({ queryKey: ['folder-access'] }),
        queryClient.invalidateQueries({ queryKey: ['file-access'] }),
      ]),
  })
}

/** The site's limits on link settings (`GET /drive/limits`). */
export interface LinkLimits {
  maxExpiryDays: number
  passwordMaxChars: number
}

export function useLinkLimits() {
  return useQuery({
    queryKey: ['drive-link-limits'],
    staleTime: 5 * 60_000,
    queryFn: async (): Promise<LinkLimits> => {
      const { data } = await api.get<{ publicLinkMaxExpiryDays: number; publicLinkPasswordMaxChars: number }>('/drive/limits')
      return { maxExpiryDays: data.publicLinkMaxExpiryDays, passwordMaxChars: data.publicLinkPasswordMaxChars }
    },
  })
}
