import { act, renderHook } from '@testing-library/react'
import type { DragEvent } from 'react'
import { describe, expect, it, vi } from 'vitest'
import '../testI18n'
import type { VaultSession } from '../sync/vaultSession'
import type { VaultView } from '../vault/types'

const toast = vi.hoisted(() => ({ success: vi.fn(), error: vi.fn() }))
vi.mock('sonner', () => ({ toast }))
const { copies, DRAG_TYPE, GROUP_DRAG_TYPE, useEntryDrop } = await import('./entryDrop')

const group = (id: string, parentId: string | null, inRecycleBin = false) => ({ id, parentId, name: id, inRecycleBin })
const view = {
  rootGroupId: 'root',
  recycleBinId: 'bin',
  recycleBinEnabled: true,
  groups: [group('root', null), group('work', 'root'), group('home', 'root'), group('bin', 'root', true)],
  entries: [{ id: 'e1', groupId: 'work', inRecycleBin: false }],
} as unknown as VaultView

function drop(data: Record<string, string>, keys: { ctrlKey?: boolean; altKey?: boolean } = {}) {
  return {
    ctrlKey: false,
    altKey: false,
    ...keys,
    preventDefault: () => undefined,
    dataTransfer: { types: Object.keys(data), getData: (type: string) => data[type] ?? '', dropEffect: 'none' },
  } as unknown as DragEvent
}

function setup() {
  const apply = vi.fn((_op: unknown) => Promise.resolve({ id: null, changed: true }))
  const session = { canEdit: true, apply, getState: () => ({ view }) } as unknown as VaultSession
  const onDone = vi.fn()
  const { result } = renderHook(() => useEntryDrop(session, onDone))
  return { apply, onDone, result }
}

describe('dragging entries and groups', () => {
  it('copies with Ctrl or ⌥ held, as KeePassXC', () => {
    expect(copies({ ctrlKey: true, altKey: false })).toBe(true)
    expect(copies({ ctrlKey: false, altKey: true })).toBe(true)
    expect(copies({ ctrlKey: false, altKey: false })).toBe(false)
  })

  it('moves entries on a plain drop and copies them with Ctrl', () => {
    const { apply, result } = setup()
    const home = result.current.dropProps({ id: 'home', name: 'home', bin: false }) as { onDrop: (e: DragEvent) => void }
    act(() => home.onDrop(drop({ [DRAG_TYPE]: JSON.stringify(['e1']) })))
    expect(apply).toHaveBeenLastCalledWith({ op: 'moveEntries', ids: ['e1'], groupId: 'home' })
    act(() => home.onDrop(drop({ [DRAG_TYPE]: JSON.stringify(['e1']) }, { ctrlKey: true })))
    expect(apply).toHaveBeenLastCalledWith({ op: 'cloneEntries', ids: ['e1'], groupId: 'home', titleSuffix: null, history: true })
  })

  it('copies a group with ⌥, and never copies into the recycle bin', () => {
    const { apply, result } = setup()
    const home = result.current.dropProps({ id: 'home', name: 'home', bin: false }) as { onDrop: (e: DragEvent) => void }
    act(() => home.onDrop(drop({ [GROUP_DRAG_TYPE]: 'work' }, { altKey: true })))
    expect(apply).toHaveBeenLastCalledWith({ op: 'copyGroup', id: 'work', parentId: 'home' })
    apply.mockClear()
    const bin = result.current.dropProps({ id: 'bin', name: 'Recycle bin', bin: true }) as { onDrop: (e: DragEvent) => void }
    act(() => bin.onDrop(drop({ [DRAG_TYPE]: JSON.stringify(['e1']) }, { ctrlKey: true })))
    act(() => bin.onDrop(drop({ [GROUP_DRAG_TYPE]: 'work' }, { ctrlKey: true })))
    expect(apply).not.toHaveBeenCalled()
  })
})
