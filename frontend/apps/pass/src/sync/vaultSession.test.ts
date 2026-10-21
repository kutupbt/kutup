import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { DriveFile, Folder } from '@kutup/drive-core/model'

// The worker's vault, as far as a key change touches it.
const handle = vi.hoisted(() => ({
  view: vi.fn(() => Promise.resolve({ name: 'Kasa', entries: [], groups: [] })),
  changeKey: vi.fn(() => Promise.resolve({ passwordShowable: true })),
  save: vi.fn(() => Promise.resolve(new Uint8Array([1]))),
  keyChangeSaved: vi.fn(() => Promise.resolve()),
  abandonKeyChange: vi.fn(() => Promise.resolve()),
  close: vi.fn(() => Promise.resolve()),
  merge: vi.fn(),
}))
vi.mock('../vault/client', () => ({
  VaultError: class VaultError extends Error {},
  VaultHandle: { open: vi.fn(() => Promise.resolve(handle)) },
}))
const drive = vi.hoisted(() => ({
  saveVaultVersion: vi.fn(),
}))
vi.mock('../drive/vaults', () => ({
  ORIGINAL: 'original',
  readCurrentVault: vi.fn(() => Promise.resolve({ contents: new Uint8Array([0]), version: 'v1' })),
  readVaultVersion: vi.fn(() => Promise.resolve(new Uint8Array([2]))),
  refreshVaultFile: vi.fn((_folder: unknown, file: unknown) => Promise.resolve(file)),
  saveVaultVersion: drive.saveVaultVersion,
  vaultTitle: (name: string) => name.replace(/\.kdbx$/i, ''),
}))
vi.mock('./outbox', () => ({
  outbox: { get: vi.fn(() => Promise.resolve(null)), put: vi.fn(() => Promise.resolve()) },
}))
vi.mock('@kutup/collab/api', () => ({
  VersionConflictError: class VersionConflictError extends Error {
    constructor(readonly current: string) {
      super('version conflict')
    }
  },
  listVersions: vi.fn(() => Promise.resolve([])),
}))

const { KeyChangeError, VaultSession } = await import('./vaultSession')
const { VersionConflictError } = await import('@kutup/collab/api')

const file = { id: 'f1', name: 'Kasa.kdbx' } as DriveFile
const folder = { id: 'c1' } as Folder
/** What axios throws when no answer came back. */
const noAnswer = Object.assign(new Error('Network Error'), { isAxiosError: true })
const refused = Object.assign(new Error('Request failed with status code 500'), { isAxiosError: true, response: { status: 500 } })

async function opened() {
  return VaultSession.open(folder, file, { password: 'eski', keyFile: null }, 'u1', true)
}

describe('a vault key change', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    drive.saveVaultVersion.mockReset()
  })

  it('kept when its save got no answer, and what was to follow it runs once Drive holds it', async () => {
    const session = await opened()
    const whenSaved = vi.fn(() => Promise.resolve())
    drive.saveVaultVersion.mockRejectedValueOnce(noAnswer)
    const failure = await session.changeKey({ password: { set: 'yeni' }, keyFile: 'keep' }, whenSaved).catch((e: unknown) => e)
    expect(failure).toBeInstanceOf(KeyChangeError)
    expect((failure as InstanceType<typeof KeyChangeError>).failure).toBe('pending')
    // Not undone: Drive may hold it already.
    expect(handle.abandonKeyChange).not.toHaveBeenCalled()
    expect(whenSaved).not.toHaveBeenCalled()
    expect(session.getState().status).toBe('offline')

    // Kutup answers: saved under the new key, then the kept key follows, once.
    drive.saveVaultVersion.mockResolvedValueOnce({ version: 'v2', file })
    await session.save()
    expect(handle.keyChangeSaved).toHaveBeenCalled()
    await vi.waitFor(() => expect(whenSaved).toHaveBeenCalledWith({ passwordShowable: true }))
    expect(session.getState().status).toBe('saved')
    // A later save runs nothing more.
    drive.saveVaultVersion.mockResolvedValueOnce({ version: 'v3', file })
    await session.save()
    expect(whenSaved).toHaveBeenCalledTimes(1)
    await session.close()
  })

  it('undone when Drive answered and refused, or another device saved first', async () => {
    const session = await opened()
    const whenSaved = vi.fn(() => Promise.resolve())
    drive.saveVaultVersion.mockRejectedValueOnce(refused)
    await expect(session.changeKey({ password: { set: 'yeni' }, keyFile: 'keep' }, whenSaved)).rejects.toMatchObject({ failure: 'failed' })
    expect(handle.abandonKeyChange).toHaveBeenCalledTimes(1)

    drive.saveVaultVersion.mockRejectedValueOnce(new VersionConflictError('v9'))
    await expect(session.changeKey({ password: { set: 'yeni' }, keyFile: 'keep' }, whenSaved)).rejects.toMatchObject({ failure: 'conflict' })
    expect(handle.abandonKeyChange).toHaveBeenCalledTimes(2)
    expect(whenSaved).not.toHaveBeenCalled()
    await session.close()
  })

  it('made at once when Drive takes it, with nothing deferred', async () => {
    const session = await opened()
    const whenSaved = vi.fn(() => Promise.resolve())
    drive.saveVaultVersion.mockResolvedValueOnce({ version: 'v2', file })
    await expect(session.changeKey({ password: 'keep', shownPassword: 'eski', keyFile: 'keep' }, whenSaved)).resolves.toEqual({ passwordShowable: true })
    expect(handle.keyChangeSaved).toHaveBeenCalledTimes(1)
    expect(whenSaved).not.toHaveBeenCalled()
    await session.close()
  })

  it('done when the save that got no answer had landed: the retry finds it under the new key', async () => {
    const session = await opened()
    const whenSaved = vi.fn(() => Promise.resolve())
    drive.saveVaultVersion.mockRejectedValueOnce(noAnswer)
    await expect(session.changeKey({ password: { set: 'yeni' }, keyFile: 'keep' }, whenSaved)).rejects.toMatchObject({ failure: 'pending' })
    // No second key change meanwhile: undoing it would bring the first key back.
    await expect(session.changeKey({ password: { set: 'üçüncü' }, keyFile: 'keep' })).rejects.toMatchObject({ failure: 'notReady' })

    // The retry: Drive has v2 (ours, under the new key) already.
    drive.saveVaultVersion.mockRejectedValueOnce(new VersionConflictError('v2'))
    handle.merge.mockResolvedValueOnce({ report: { conflicts: [], groupConflicts: [], metadataConflicts: [], restored: [] }, differsFromTheirs: false, theirsUnderCurrentKey: true })
    await session.save()
    await vi.waitFor(() => expect(whenSaved).toHaveBeenCalledTimes(1))
    expect(handle.keyChangeSaved).toHaveBeenCalledTimes(1)
    expect(drive.saveVaultVersion).toHaveBeenCalledTimes(2)
    expect(session.getState().status).toBe('saved')
    await session.close()
  })

  it('saved again under the new key when another device saved under the old one meanwhile', async () => {
    const session = await opened()
    const whenSaved = vi.fn(() => Promise.resolve())
    drive.saveVaultVersion.mockRejectedValueOnce(noAnswer)
    await expect(session.changeKey({ password: { set: 'yeni' }, keyFile: 'keep' }, whenSaved)).rejects.toMatchObject({ failure: 'pending' })

    // Theirs opens only with the old key: taken in, never adopted; ours goes up under the new one.
    drive.saveVaultVersion.mockRejectedValueOnce(new VersionConflictError('v2'))
    handle.merge.mockResolvedValueOnce({ report: { conflicts: [], groupConflicts: [], metadataConflicts: [], restored: [] }, differsFromTheirs: true, theirsUnderCurrentKey: false })
    drive.saveVaultVersion.mockResolvedValueOnce({ version: 'v3', file })
    await session.save()
    await vi.waitFor(() => expect(whenSaved).toHaveBeenCalledTimes(1))
    expect(drive.saveVaultVersion).toHaveBeenCalledTimes(3)
    expect(session.getState().status).toBe('saved')
    await session.close()
  })
})
