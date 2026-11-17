import { describe, expect, it } from 'vitest'
import type { GroupView } from '../vault/types'
import { canDropGroup, deletedGroups, groupTargets, isWithin } from './groupMoves'

function g(id: string, parentId: string | null, inRecycleBin = false): GroupView {
  return {
    id,
    parentId,
    depth: 0,
    name: id,
    notes: '',
    icon: null,
    hasCustomIcon: false,
    customIcon: null,
    tags: [],
    expires: false,
    expiry: null,
    isRecycleBin: id === 'bin',
    inRecycleBin,
  }
}

// root ─ work ─ servers ─ prod
//      ├ home
//      └ bin ─ old ─ older
const view = {
  rootGroupId: 'root',
  recycleBinId: 'bin',
  groups: [
    g('root', null),
    g('work', 'root'),
    g('servers', 'work'),
    g('prod', 'servers'),
    g('home', 'root'),
    g('bin', 'root', true),
    g('old', 'bin', true),
    g('older', 'old', true),
  ],
}
const ids = (groups: GroupView[]) => groups.map((x) => x.id)
const find = (id: string) => view.groups.find((x) => x.id === id)!

describe('moving groups', () => {
  it('knows what is inside a group', () => {
    expect(isWithin(view, 'prod', 'work')).toBe(true)
    expect(isWithin(view, 'work', 'work')).toBe(true)
    expect(isWithin(view, 'home', 'work')).toBe(false)
  })

  it('offers every group outside the bin but itself, what it holds and where it is', () => {
    expect(ids(groupTargets(view, find('servers')))).toEqual(['root', 'home'])
    expect(ids(groupTargets(view, find('home')))).toEqual(['work', 'servers', 'prod'])
  })

  it('never moves the top group or the bin', () => {
    expect(groupTargets(view, find('root'))).toEqual([])
    expect(groupTargets(view, find('bin'))).toEqual([])
  })

  it('drops onto a target or the bin, never into itself', () => {
    expect(canDropGroup(view, 'servers', 'home')).toBe(true)
    expect(canDropGroup(view, 'servers', 'bin')).toBe(true)
    expect(canDropGroup(view, 'work', 'prod')).toBe(false)
    expect(canDropGroup(view, 'servers', 'work')).toBe(false)
    expect(canDropGroup(view, 'old', 'home')).toBe(false)
    expect(canDropGroup(view, 'root', 'home')).toBe(false)
  })

  it('lists the groups directly in the bin', () => {
    expect(ids(deletedGroups(view))).toEqual(['old'])
    expect(deletedGroups({ ...view, recycleBinId: null })).toEqual([])
  })
})
