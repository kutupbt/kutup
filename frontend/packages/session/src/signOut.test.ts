// @vitest-environment jsdom
import 'fake-indexeddb/auto'
import { beforeEach, describe, expect, it, vi } from 'vitest'

// The head's engine needs WASM; its copies' prefix is all a sign-out uses.
vi.mock('./accountHead', async () => {
  const { indexedDbRecordsStore } = await import('./accountRecords')
  return {
    forgetAccountRecords: async (session: { accountId: string }) => indexedDbRecordsStore().clearPrefix(`lsn-${session.accountId}:`),
  }
})

import { indexedDbRecordsStore } from './accountRecords'
import { clearAccountData, registerSignOutCleanup } from './signOut'
import type { Session } from './store'

async function createDatabase(name: string): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const request = indexedDB.open(name, 1)
    request.onupgradeneeded = () => request.result.createObjectStore('s')
    request.onsuccess = () => {
      request.result.close()
      resolve()
    }
    request.onerror = () => reject(request.error)
  })
}

const names = async () => (await indexedDB.databases()).map((db) => db.name!).sort()

beforeEach(async () => {
  localStorage.clear()
  for (const name of await names()) {
    await new Promise<void>((resolve) => {
      const request = indexedDB.deleteDatabase(name)
      request.onsuccess = () => resolve()
      request.onerror = () => resolve()
    })
  }
})

describe('sign-out', () => {
  it("leaves nothing of the account on this origin but its anchors, and another account's data alone", async () => {
    const records = indexedDbRecordsStore()
    const row = { revision: 1, envelope: 'e' }
    await records.save('lsn-A:pins', 3, { puts: [['x', row]], deletes: [], reset: true })
    await records.save('lsn-B:pins', 5, { puts: [['y', row]], deletes: [], reset: true })
    localStorage.setItem('kutup.chat.deviceId:A', '2')
    localStorage.setItem('kutup.chat.drafts:A', 'sealed')
    localStorage.setItem('kutup.account.manifestPins:A', 'pin')
    localStorage.setItem('kutup.chat.deviceId:B', '3')
    localStorage.setItem('kutup.ui.theme', 'dark')
    await createDatabase('kutup.chat.store:A')
    await createDatabase('kutup.chat.backup:A')
    await createDatabase('kutup.pass.outbox:A')
    await createDatabase('kutup.chat.store:B')
    await createDatabase('kutup.account.revisionsSeen')
    const cleanup = vi.fn(async () => undefined)
    registerSignOutCleanup(cleanup)

    await clearAccountData({ accountId: 'A' } as Session)

    expect(await records.load('lsn-A:pins')).toBeNull()
    expect(await records.load('lsn-B:pins')).toEqual({ cursor: 5, records: [['y', row]] })
    expect(localStorage.getItem('kutup.chat.deviceId:A')).toBeNull()
    expect(localStorage.getItem('kutup.chat.drafts:A')).toBeNull()
    expect(localStorage.getItem('kutup.account.manifestPins:A')).toBe('pin')
    expect(localStorage.getItem('kutup.chat.deviceId:B')).toBe('3')
    expect(localStorage.getItem('kutup.ui.theme')).toBe('dark')
    expect(await names()).toEqual(['kutup.account.records', 'kutup.account.revisionsSeen', 'kutup.chat.store:B'])
    expect(cleanup).toHaveBeenCalledWith({ accountId: 'A' })
  })
})
