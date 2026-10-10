import { describe, expect, it } from 'vitest'
import { flattenFolders, folderPath, heightOf, nameIsFree, reorder, type MailFolder, type MailPlaces } from './places'

function folder(id: string, name: string, depth: number, children: MailFolder[] = [], parentId: string | null = null): MailFolder {
  return { id, parentId, name, color: '#8080ff', position: 0, expanded: true, notify: true, depth, children }
}

describe('places', () => {
  const acme = folder('c', 'Acme', 3, [], 'b')
  const clients = folder('b', 'Müşteriler', 2, [acme], 'a')
  const work = folder('a', 'İş', 1, [clients])
  const places: MailPlaces = {
    tree: [work],
    folders: new Map([work, clients, acme].map((f) => [f.id, f])),
    labels: [],
    labelsById: new Map(),
    unreadable: 0,
  }

  it('walks the tree', () => {
    expect(flattenFolders(places.tree).map((f) => f.id)).toEqual(['a', 'b', 'c'])
    expect(folderPath(places, 'c')).toBe('İş / Müşteriler / Acme')
    expect(heightOf(work)).toBe(3)
    expect(heightOf(acme)).toBe(1)
  })

  it('checks names among siblings, ignoring case and spaces', () => {
    const siblings = [{ id: '1', name: 'Faturalar' }, { id: '2', name: 'İş' }]
    expect(nameIsFree(' faturalar ', siblings)).toBe(false)
    expect(nameIsFree('Faturalar', siblings, '1')).toBe(true)
    expect(nameIsFree('Seyahat', siblings)).toBe(true)
    // Turkish dotted and dotless i are one letter here, in either case.
    expect(nameIsFree('iş', siblings)).toBe(false)
    expect(nameIsFree('IŞ', siblings)).toBe(false)
    expect(nameIsFree('ış', siblings)).toBe(false)
  })

  it('reorders and saves only the positions that changed', () => {
    const list = ['a', 'b', 'c', 'd'].map((id, position) => ({ id, position }))
    expect(reorder(list, 'd', 0)).toEqual([
      { id: 'd', position: 0 },
      { id: 'a', position: 1 },
      { id: 'b', position: 2 },
      { id: 'c', position: 3 },
    ])
    expect(reorder(list, 'a', 1)).toEqual([
      { id: 'b', position: 0 },
      { id: 'a', position: 1 },
    ])
    expect(reorder(list, 'x', 0)).toEqual([])
  })
})
