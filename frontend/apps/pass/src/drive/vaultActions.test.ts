import { describe, expect, it, vi } from 'vitest'

vi.mock('@kutup/drive-core/move', () => ({ moveFile: vi.fn() }))
vi.mock('./vaults', () => ({ vaultTitle: (name: string) => name.replace(/\.kdbx$/i, '') }))
vi.mock('./secrets', () => ({}))
vi.mock('../vault/client', () => ({ VaultHandle: {} }))

const { moveTargets } = await import('./vaultActions')

type F = Parameters<typeof moveTargets>[0][number]
const folder = (id: string, over: Partial<F> = {}): F =>
  ({ id, key: new Uint8Array(32), canUpload: true, source: 'owned', ownerUserId: 'me', isRoot: false, name: id, ...over }) as F

describe('moveTargets', () => {
  it('offers the open folders of the same owner one can write to, never its own, My files first', () => {
    const here = folder('here')
    const vault = { folder: here, file: { id: 'v', name: 'Kasa.kdbx' }, owner: null, canEdit: true } as never
    const targets = moveTargets(
      [
        here,
        folder('b'),
        folder('root', { isRoot: true }),
        folder('locked', { key: null }),
        folder('readOnly', { canUpload: false }),
        folder('theirs', { ownerUserId: 'someone' }),
        folder('remote', { source: 'remote' }),
        folder('a'),
      ],
      vault,
    )
    expect(targets.map((f) => f.id)).toEqual(['root', 'a', 'b'])
  })
})
