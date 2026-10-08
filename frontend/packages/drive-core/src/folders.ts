import { useQuery, useQueryClient, type QueryClient } from '@tanstack/react-query'
import { isAxiosError } from 'axios'
import { createOwnedCollectionV1, openOwnedCollectionV1, openSharedCollectionV1 } from '@kutup/crypto'
import api from '@kutup/session/client'
import type { CollectionRow } from '@kutup/session/api-types'
import { useDriveIdentity, type DriveIdentity } from './identity'
import { ROOT_NAME, type Folder } from './model'
import { atTopLevel, fillInNames, nameHashIn } from './names'

export const foldersKey = ['folders'] as const

export interface CollectionRowWithTimes extends CollectionRow {
  createdAt: string
  updatedAt: string
}

export interface IncomingShare {
  id: string
  remoteDomain: string
  remoteCollectionId: string
  namedShareEnvelope: string
  nameEnvelope: string
  keyEpoch: number
  nameRevision: number
  epochStatement: string
  epochStatementHash: string
  ownerUserId: string
  ownerAccount: string
  ownerIncarnationId: string
  ownerSigningPublicKey: string
  ownerAuthorityPublicKey: string
  canUpload: boolean
  canDelete: boolean
  uploadQuotaBytes: number | null
  /** `folder` or `album`: Drive lists folders, Photos albums. */
  collectionKind: 'folder' | 'album'
  createdAt: string
}

/**
 * Decryption is the slow part of listing (an envelope, a verified epoch
 * statement, a name). Results are cached per exact envelope set, so a refetch
 * after any mutation only decrypts what changed.
 */
const opened = new Map<string, Promise<{ collectionKey: Uint8Array; name: string } | null>>()

function openOnce(cacheKey: string, open: () => Promise<{ collectionKey: Uint8Array; name: string }>) {
  let pending = opened.get(cacheKey)
  if (!pending) {
    pending = open().catch(() => null)
    opened.set(cacheKey, pending)
  }
  return pending
}

/** A collection as this account opens it: its own, or one shared with it. */
export async function openRow(row: CollectionRowWithTimes, me: DriveIdentity): Promise<Folder> {
  const owned = row.ownerUserId === me.userId
  const result = owned
    ? await openOnce(`o:${row.ownerKeyEnvelope}:${row.nameEnvelope}`, () =>
        openOwnedCollectionV1(row, me.masterKey),
      )
    : await openOnce(`s:${row.namedShareEnvelope}:${row.nameEnvelope}`, () =>
        openSharedCollectionV1(
          {
            ...row,
            namedShareEnvelope: row.namedShareEnvelope ?? '',
            ownerAccount: row.ownerAccount ?? '',
            ownerIncarnationId: row.ownerIncarnationId ?? '',
            ownerDriveSigningPublicKey: row.ownerDriveSigningPublicKey ?? '',
            ownerAuthorityPublicKey: row.ownerAuthorityPublicKey ?? '',
          },
          me.privateKey,
          me.account,
          me.incarnationId,
        ),
      )
  return {
    source: owned ? 'owned' : 'shared',
    id: row.id,
    parentId: row.parentCollectionId ?? null,
    name: result?.name ?? null,
    key: result?.collectionKey ?? null,
    keyEpoch: row.keyEpoch,
    ownerUserId: row.ownerUserId,
    ownerAuthorityPublicKey: owned ? me.authorityPublicKey : (row.ownerAuthorityPublicKey ?? ''),
    epochStatementHash: row.epochStatementHash,
    nameRevision: row.nameRevision,
    color: row.color ?? null,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
    ownerAccount: owned ? null : (row.ownerAccount ?? null),
    canUpload: owned || row.canUpload === true,
    canDelete: owned || row.canDelete === true,
    canManage: owned,
    isRoot: owned && !row.parentCollectionId && result?.name === ROOT_NAME,
    nameHash: row.nameHash ?? null,
  }
}

/** A share from another server, verified and opened; null when it does not verify. */
export async function openRemote(share: IncomingShare, me: DriveIdentity): Promise<Folder | null> {
  const result = await openOnce(`r:${share.id}:${share.namedShareEnvelope}:${share.nameEnvelope}`, () =>
    openSharedCollectionV1(
      {
        id: share.remoteCollectionId,
        ownerUserId: share.ownerUserId,
        nameEnvelope: share.nameEnvelope,
        namedShareEnvelope: share.namedShareEnvelope,
        keyEpoch: share.keyEpoch,
        nameRevision: share.nameRevision,
        epochStatement: share.epochStatement,
        epochStatementHash: share.epochStatementHash,
        ownerAccount: share.ownerAccount,
        ownerIncarnationId: share.ownerIncarnationId,
        ownerDriveSigningPublicKey: share.ownerSigningPublicKey,
        ownerAuthorityPublicKey: share.ownerAuthorityPublicKey,
      },
      me.privateKey,
      me.account,
      me.incarnationId,
    ),
  )
  // A share that does not verify is not shown: it cannot be opened, and
  // naming it "[encrypted]" would invite trusting an unverified sender.
  if (!result) return null
  return {
    source: 'remote',
    id: share.remoteCollectionId,
    remoteShareId: share.id,
    parentId: null,
    name: result.name,
    key: result.collectionKey,
    keyEpoch: share.keyEpoch,
    ownerUserId: share.ownerUserId,
    ownerAuthorityPublicKey: share.ownerAuthorityPublicKey,
    epochStatementHash: share.epochStatementHash,
    nameRevision: share.nameRevision,
    color: null,
    createdAt: share.createdAt,
    updatedAt: share.createdAt,
    ownerAccount: share.ownerAccount,
    canUpload: share.canUpload,
    canDelete: share.canDelete,
    canManage: false,
    isRoot: false,
  }
}

export interface FolderIndex {
  all: Folder[]
  byId: Map<string, Folder>
  root: Folder
  /** Owned top-level folders other than the root (restored from trash, made by the CLI). */
  looseTopLevel: Folder[]
  sharedWithMe: Folder[]
  childrenOf: (id: string) => Folder[]
}

function index(folders: Folder[]): FolderIndex {
  // Two tabs opening a brand-new account can each create a root; the oldest
  // wins everywhere, and any other shows up as an ordinary top-level folder.
  const roots = folders.filter((f) => f.isRoot).sort((a, b) => a.createdAt.localeCompare(b.createdAt))
  const root = roots[0]
  if (!root) throw new Error('the root folder is missing')
  for (const extra of roots.slice(1)) extra.isRoot = false
  const byId = new Map(folders.map((f) => [f.id, f]))
  const children = new Map<string, Folder[]>()
  for (const f of folders) {
    if (!f.parentId) continue
    children.set(f.parentId, [...(children.get(f.parentId) ?? []), f])
  }
  return {
    all: folders,
    byId,
    root,
    looseTopLevel: folders.filter((f) => f.source === 'owned' && !f.parentId && !f.isRoot),
    // Sharing is not recursive: every shared folder the server lists is its own entry.
    sharedWithMe: folders.filter((f) => f.source !== 'owned'),
    childrenOf: (id) => children.get(id) ?? [],
  }
}

async function loadFolders(me: DriveIdentity): Promise<FolderIndex> {
  const fetchAll = async () => {
    const [{ data: rows }, { data: shares }] = await Promise.all([
      api.get<CollectionRowWithTimes[]>('/collections'),
      api.get<IncomingShare[]>('/drive/federation/shares'),
    ])
    const local = await Promise.all(rows.map((row) => openRow(row, me)))
    const remote = (await Promise.all(shares.map((s) => openRemote(s, me)))).filter((f): f is Folder => f !== null)
    return [...local, ...remote]
  }
  let folders = await fetchAll()
  if (!folders.some((f) => f.isRoot)) {
    // First visit: every account keeps its top-level files in one root folder.
    const created = await createOwnedCollectionV1(me.masterKey, me.userId, ROOT_NAME, null)
    try {
      await api.post('/collections', { ...created.payload, nameHash: await nameHashIn(atTopLevel(me.masterKey), ROOT_NAME) })
    } catch (error) {
      // Another tab made it first: its name is taken at the top level.
      if (!(isAxiosError(error) && error.response?.status === 409)) throw error
    }
    folders = await fetchAll()
  }
  return index(folders)
}

const filling = new Set<string>()

/**
 * Fill in the name hashes of the account's top-level folders made before
 * names were kept unique (docs/plans/drive-unique-names.md), in the
 * background; the folders reload when anything changed.
 */
function fillTopLevel(folders: FolderIndex, me: DriveIdentity, queryClient: QueryClient) {
  const top = folders.all.filter((f) => f.source === 'owned' && !f.parentId)
  if (!top.some((f) => !f.nameHash) || filling.has(me.userId)) return
  filling.add(me.userId)
  void fillInNames(atTopLevel(me.masterKey), [], top, me.userId, null)
    .then((changed) => (changed ? queryClient.invalidateQueries({ queryKey: foldersKey }) : undefined))
    .catch((error) => console.warn('names: could not fill in top-level names', error))
    .finally(() => filling.delete(me.userId))
}

/** Every folder the account can see — owned, shared with it, and federated — decrypted. */
/**
 * The folder index as last loaded. It is cached per account
 * (`[...foldersKey, userId]`), so it is found by prefix, not read by exact key.
 */
export function cachedFolderIndex(queryClient: QueryClient): FolderIndex | undefined {
  return queryClient
    .getQueriesData<FolderIndex>({ queryKey: foldersKey })
    .map(([, data]) => data)
    .find((data): data is FolderIndex => Boolean(data))
}

export function useFolders() {
  const identity = useDriveIdentity()
  const queryClient = useQueryClient()
  return useQuery({
    queryKey: [...foldersKey, identity.data?.userId],
    enabled: identity.isSuccess,
    queryFn: async () => {
      const folders = await loadFolders(identity.data!)
      fillTopLevel(folders, identity.data!, queryClient)
      return folders
    },
  })
}
