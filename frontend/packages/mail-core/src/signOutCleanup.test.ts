// @vitest-environment jsdom
import 'fake-indexeddb/auto'
import { describe, expect, it, vi } from 'vitest'

vi.mock('./searchWasm', () => ({ mailSearchStoreName: (key: string) => Promise.resolve(`hmac-of-${key}`) }))

const { forgetMailSearch } = await import('./signOutCleanup')

async function createDatabase(name: string): Promise<void> {
  await new Promise<void>((resolve) => {
    const request = indexedDB.open(name, 1)
    request.onsuccess = () => {
      request.result.close()
      resolve()
    }
  })
}

describe("a sign-out's Mail part", () => {
  it("deletes the account's search index, named from its object-id key, and no other", async () => {
    await createDatabase('kutup.mail.search:hmac-of-keyA')
    await createDatabase('kutup.mail.search:hmac-of-keyB')
    await forgetMailSearch({ roots: { objectIdKey: 'keyA' } } as never)
    expect((await indexedDB.databases()).map((db) => db.name)).toEqual(['kutup.mail.search:hmac-of-keyB'])
  })
})
