import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  chatDeviceDatabaseName,
  completeRequestedLocalChatDeviceReset,
  requestLocalChatDeviceReset,
  resetLocalChatDevice,
} from './local-store'

describe('local Chat device store', () => {
  afterEach(() => {
    vi.restoreAllMocks()
    vi.unstubAllGlobals()
  })

  it("names the device database by the account's permanent id", async () => {
    expect(await chatDeviceDatabaseName('account-1')).toBe('kutup.chat.store:account-1')
    expect(await chatDeviceDatabaseName('account-2')).toBe('kutup.chat.store:account-2')
  })

  it('deletes only the account-scoped device database', async () => {
    const request = {} as IDBOpenDBRequest
    const deleteDatabase = vi.fn(() => {
      queueMicrotask(() => request.onsuccess?.(new Event('success')))
      return request
    })
    vi.stubGlobal('indexedDB', { deleteDatabase })

    const expected = await chatDeviceDatabaseName('account-1')
    await resetLocalChatDevice('account-1')

    expect(deleteDatabase).toHaveBeenCalledOnce()
    expect(deleteDatabase).toHaveBeenCalledWith(expected)
    expect(deleteDatabase).not.toHaveBeenCalledWith(`${expected}:continuous-backup`)
  })

  it('completes only an explicitly requested reset after navigation', async () => {
    const request = {} as IDBOpenDBRequest
    const deleteDatabase = vi.fn(() => {
      queueMicrotask(() => request.onsuccess?.(new Event('success')))
      return request
    })
    vi.stubGlobal('indexedDB', { deleteDatabase })

    expect(await completeRequestedLocalChatDeviceReset('account-1')).toBe(false)
    requestLocalChatDeviceReset('account-1')
    expect(await completeRequestedLocalChatDeviceReset('account-2')).toBe(false)
    expect(await completeRequestedLocalChatDeviceReset('account-1')).toBe(true)
    expect(await completeRequestedLocalChatDeviceReset('account-1')).toBe(false)
    expect(deleteDatabase).toHaveBeenCalledOnce()
  })
})
