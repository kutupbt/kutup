import { afterEach, describe, expect, it, vi } from 'vitest'

const server = vi.hoisted(() => ({ stored: { theme: 'dark', language: 'tr' } as Record<string, unknown>, puts: [] as unknown[], fail: false }))
vi.mock('./client', () => ({
  default: {
    get: () => Promise.resolve({ data: server.stored }),
    put: (_path: string, body: unknown) => {
      server.puts.push(body)
      return server.fail ? Promise.reject(new Error('offline')) : Promise.resolve({ data: body })
    },
  },
}))

import { isShortcutKey, setShortcutsEnabled, shortcutsEnabled, takeAccountShortcuts } from './shortcuts'

function press(key: string, target: Element = document.body, init: KeyboardEventInit = {}): KeyboardEvent {
  const event = new KeyboardEvent('keydown', { key, bubbles: true, ...init })
  Object.defineProperty(event, 'target', { value: target })
  return event
}

afterEach(() => {
  takeAccountShortcuts(null)
  document.body.innerHTML = ''
  server.puts = []
  server.fail = false
})

describe('keyboard shortcuts', () => {
  it('are on until the account turns them off', () => {
    takeAccountShortcuts(null)
    expect(shortcutsEnabled()).toBe(true)
    expect(isShortcutKey(press('w'))).toBe(true)
    takeAccountShortcuts(false)
    expect(isShortcutKey(press('w'))).toBe(false)
  })

  it('never take a key typed into a field, a dialog, or one with a modifier', () => {
    const input = document.createElement('input')
    document.body.append(input)
    expect(isShortcutKey(press('w', input))).toBe(false)
    expect(isShortcutKey(press('w', document.body, { ctrlKey: true }))).toBe(false)
    expect(isShortcutKey(press('w', document.body, { metaKey: true }))).toBe(false)
    const dialog = document.createElement('div')
    dialog.setAttribute('role', 'dialog')
    dialog.setAttribute('data-state', 'open')
    document.body.append(dialog)
    expect(isShortcutKey(press('w'))).toBe(false)
  })

  it("save the choice with the account's theme and language, and undo it when the save fails", async () => {
    await setShortcutsEnabled(false)
    expect(server.puts).toEqual([{ theme: 'dark', language: 'tr', shortcuts: false }])
    expect(shortcutsEnabled()).toBe(false)
    server.fail = true
    await expect(setShortcutsEnabled(true)).rejects.toThrow('offline')
    expect(shortcutsEnabled()).toBe(false)
  })
})
