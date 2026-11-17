// @vitest-environment jsdom
import 'fake-indexeddb/auto'
import { beforeEach, describe, expect, it } from 'vitest'
import { INSTANCE_KEY, reconcileInstance, takeServerResetNotice } from './instance'

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

async function databaseNames(): Promise<string[]> {
  return (await indexedDB.databases()).map((db) => db.name!).sort()
}

beforeEach(async () => {
  localStorage.clear()
  sessionStorage.clear()
  for (const name of await databaseNames()) {
    await new Promise<void>((resolve) => {
      const request = indexedDB.deleteDatabase(name)
      request.onsuccess = () => resolve()
      request.onerror = () => resolve()
    })
  }
})

describe('the server instance id', () => {
  it('a first visit remembers the id and clears nothing', async () => {
    localStorage.setItem('kutup.ui.theme', 'dark')
    expect(await reconcileInstance('A')).toBe(false)
    expect(localStorage.getItem(INSTANCE_KEY)).toBe('A')
    expect(localStorage.getItem('kutup.ui.theme')).toBe('dark')
    expect(takeServerResetNotice()).toBe(false)
  })

  it('the same id touches nothing', async () => {
    localStorage.setItem(INSTANCE_KEY, 'A')
    localStorage.setItem('kutup.session', 'blob')
    await createDatabase('kutup.chat.store:x')
    expect(await reconcileInstance('A')).toBe(false)
    expect(localStorage.getItem('kutup.session')).toBe('blob')
    expect(await databaseNames()).toEqual(['kutup.chat.store:x'])
  })

  it('another id clears every store but the anchors and the look', async () => {
    localStorage.setItem(INSTANCE_KEY, 'A')
    localStorage.setItem('kutup.session', 'blob')
    localStorage.setItem('kutup.chat.prefs', '{}')
    localStorage.setItem('kutup.account.manifestPins:abc', 'pin')
    localStorage.setItem('kutup.ui.theme', 'dark')
    localStorage.setItem('other-site', 'kept')
    sessionStorage.setItem('kutup.session.fork:x', '/')
    await createDatabase('kutup.chat.store:x')
    await createDatabase('kutup.account.records')
    await createDatabase('kutup.drive.revisionsSeen')

    expect(await reconcileInstance('B')).toBe(true)

    expect(localStorage.getItem(INSTANCE_KEY)).toBe('B')
    expect(localStorage.getItem('kutup.session')).toBeNull()
    expect(localStorage.getItem('kutup.chat.prefs')).toBeNull()
    expect(localStorage.getItem('kutup.account.manifestPins:abc')).toBe('pin')
    expect(localStorage.getItem('kutup.ui.theme')).toBe('dark')
    expect(localStorage.getItem('other-site')).toBe('kept')
    expect(sessionStorage.getItem('kutup.session.fork:x')).toBeNull()
    expect(await databaseNames()).toEqual(['kutup.drive.revisionsSeen'])
    expect(takeServerResetNotice()).toBe(true)
    expect(takeServerResetNotice()).toBe(false)
  })

  it('no id remembered but older Kutup data present: cleared (the browsers from before ids)', async () => {
    localStorage.setItem('kutup-session', 'old blob')
    localStorage.setItem('kutup:chat:device-id:u', '7')
    await createDatabase('kutup-chat-v2:abcd')
    await createDatabase('kutup-revisions-v2')

    expect(await reconcileInstance('B')).toBe(true)

    expect(localStorage.getItem('kutup-session')).toBeNull()
    expect(localStorage.getItem('kutup:chat:device-id:u')).toBeNull()
    expect(await databaseNames()).toEqual(['kutup-revisions-v2'])
  })
})
