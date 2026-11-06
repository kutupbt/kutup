import { beforeEach, describe, expect, it, vi } from 'vitest'

// The library record as this browser reads it: what the server says of the
// record must be what the record says, and an older record than this
// browser has seen (or none at all) is refused.

const get = vi.fn<(url: string) => Promise<{ data: unknown }>>()
vi.mock('@kutup/session/client', () => ({ default: { get: (url: string) => get(url), put: vi.fn() } }))

const header = { accountIncarnationId: 'aa'.repeat(32), revision: 2, previousDigest: '11'.repeat(32) }
const crypto = {
  openPhotosLibrary: vi.fn(() => Promise.resolve({ marks: { favourites: ['f'], archived: [], hidden: [] }, header })),
  photosLibraryDigest: vi.fn(() => Promise.resolve('22'.repeat(32))),
  sealPhotosLibrary: vi.fn(),
}
vi.mock('@kutup/crypto/photosLibrary', () => crypto)
vi.mock('@kutup/drive-core/identity', () => ({ useDriveIdentity: vi.fn() }))

const { loadMarks } = await import('./marks')

const me = { userId: 'u', binding: 'b', incarnationId: 'aa'.repeat(32), masterKey: new Uint8Array(32) } as never
const stored = (revision: number, envelopeDigest = '22'.repeat(32)) => ({ data: { envelope: 'ZW52', revision, envelopeDigest } })
const notFound = () => Object.assign(new Error('404'), { isAxiosError: true, response: { status: 404 } })

describe('the Photos library record, as read', () => {
  beforeEach(() => {
    localStorage.clear()
    header.revision = 2
    crypto.photosLibraryDigest.mockResolvedValue('22'.repeat(32))
  })

  it('opens a record whose header and digest are what the server says', async () => {
    get.mockResolvedValueOnce(stored(2))
    expect(await loadMarks(me)).toMatchObject({ revision: 2, digest: '22'.repeat(32) })
  })

  it('refuses a record the server describes as another revision or digest', async () => {
    get.mockResolvedValueOnce(stored(3))
    await expect(loadMarks(me)).rejects.toThrow(/differs/)
    get.mockResolvedValueOnce(stored(2, '33'.repeat(32)))
    await expect(loadMarks(me)).rejects.toThrow(/differs/)
  })

  it('refuses an older record, another at the same revision, or none, once it has seen one', async () => {
    get.mockResolvedValueOnce(stored(2))
    await loadMarks(me)

    header.revision = 1
    get.mockResolvedValueOnce(stored(1))
    await expect(loadMarks(me)).rejects.toThrow(/older/)

    header.revision = 2
    crypto.photosLibraryDigest.mockResolvedValueOnce('44'.repeat(32))
    get.mockResolvedValueOnce(stored(2, '44'.repeat(32)))
    await expect(loadMarks(me)).rejects.toThrow(/older/)

    get.mockRejectedValueOnce(notFound())
    await expect(loadMarks(me)).rejects.toThrow(/no longer/)

    // A newer one moves the pin on.
    header.revision = 3
    crypto.photosLibraryDigest.mockResolvedValueOnce('55'.repeat(32))
    get.mockResolvedValueOnce(stored(3, '55'.repeat(32)))
    expect(await loadMarks(me)).toMatchObject({ revision: 3 })
  })

  it('starts empty when there is no record and none was seen', async () => {
    get.mockRejectedValueOnce(notFound())
    expect(await loadMarks(me)).toMatchObject({ revision: 0, digest: undefined })
  })
})
