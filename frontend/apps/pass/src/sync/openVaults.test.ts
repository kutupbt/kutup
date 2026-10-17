import { describe, expect, it, vi } from 'vitest'
import type { VaultFile } from '../drive/vaults'
import { lockVault, openVault, openVaultIds } from './openVaults'
import type { VaultSession } from './vaultSession'

const open = vi.hoisted(() => vi.fn<() => Promise<VaultSession>>())
vi.mock('./vaultSession', () => ({ VaultSession: { open } }))

function vaultFile(id: string): VaultFile {
  return { file: { id }, folder: {}, canEdit: true } as unknown as VaultFile
}

function fakeSession(): VaultSession {
  return { save: vi.fn(() => Promise.resolve()), close: vi.fn(() => Promise.resolve()) } as unknown as VaultSession
}

const key = { password: 'parola', keyFile: null }

describe('openVault', () => {
  it('shows the vault only once what runs before it (keeping its key) is done', async () => {
    const session = fakeSession()
    open.mockResolvedValueOnce(session)
    let finishKeep!: () => void
    const kept = new Promise<void>((resolve) => (finishKeep = resolve))
    const beforeShown = vi.fn(() => kept)

    const opening = openVault(vaultFile('v1'), key, 'user', beforeShown)
    await vi.waitFor(() => expect(beforeShown).toHaveBeenCalledWith(session))
    // Opened, but the key is still being kept: a reload now would lose it.
    expect(openVaultIds()).not.toContain('v1')

    finishKeep()
    await expect(opening).resolves.toBe(session)
    expect(openVaultIds()).toContain('v1')
    await lockVault('v1')
  })

  it('shows the vault when what runs before it fails', async () => {
    const session = fakeSession()
    open.mockResolvedValueOnce(session)

    await expect(openVault(vaultFile('v2'), key, 'user', () => Promise.reject(new Error('keep failed')))).rejects.toThrow('keep failed')
    expect(openVaultIds()).toContain('v2')
    await lockVault('v2')
  })

  it('runs it also for a vault open already', async () => {
    const session = fakeSession()
    open.mockResolvedValueOnce(session)
    await openVault(vaultFile('v3'), key, 'user')
    const beforeShown = vi.fn(() => Promise.resolve())

    await expect(openVault(vaultFile('v3'), key, 'user', beforeShown)).resolves.toBe(session)
    expect(beforeShown).toHaveBeenCalledWith(session)
    await lockVault('v3')
  })
})
