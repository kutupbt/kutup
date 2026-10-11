import { Script } from 'node:vm'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { reloadGuard, reloadGuardScript, type GuardWindow } from './reloadGuard'

const ORIGIN = 'https://mail.kutup.dev'

/** A page whose listeners the test fires by hand. */
function page(storage = new Map<string, string>()) {
  const listeners = new Map<string, ((event: Event) => void)[]>()
  const timers: (() => void)[] = []
  const reload = vi.fn()
  const win: GuardWindow = {
    document,
    sessionStorage: {
      getItem: (k) => storage.get(k) ?? null,
      setItem: (k, v) => void storage.set(k, v),
      removeItem: (k) => void storage.delete(k),
    },
    localStorage: { getItem: () => null },
    navigator: { language: 'en-US' },
    location: { origin: ORIGIN, reload },
    addEventListener: (type, listener) => listeners.set(type, [...(listeners.get(type) ?? []), listener]),
    setTimeout: (handler) => timers.push(handler),
  }
  const fire = (type: string, target?: object) => {
    for (const listener of listeners.get(type) ?? []) listener({ target } as unknown as Event)
  }
  const scriptFailed = (src = `${ORIGIN}/assets/index-abc.js`) => fire('error', { tagName: 'SCRIPT', src })
  return { win, storage, reload, fire, scriptFailed, timers }
}

beforeEach(() => {
  document.body.innerHTML = '<div id="root"></div>'
})

describe('the reload guard', () => {
  it('reloads a blank page once when its own script fails', () => {
    const p = page()
    reloadGuard(p.win, 'b1')
    p.scriptFailed()
    p.scriptFailed()
    expect(p.reload).toHaveBeenCalledTimes(1)
    expect(p.storage.get('kutup-reload:b1')).toBe('1')
  })

  it('shows an error page with Reload, not a second reload, when it fails again', () => {
    const storage = new Map([['kutup-reload:b1', '1']])
    const p = page(storage)
    reloadGuard(p.win, 'b1')
    p.scriptFailed()
    expect(p.reload).not.toHaveBeenCalled()
    expect(document.querySelector('[role="alert"] h1')?.textContent).toBe('Kutup could not load')
    // Reload asked for by the person clears the flag.
    document.querySelector('button')!.click()
    expect(p.reload).toHaveBeenCalledTimes(1)
    expect(storage.has('kutup-reload:b1')).toBe(false)
  })

  it('leaves a page that has drawn alone, and clears the flag after it drew', () => {
    const storage = new Map([['kutup-reload:b1', '1']])
    const p = page(storage)
    reloadGuard(p.win, 'b1')
    document.getElementById('root')!.innerHTML = '<p>Inbox</p>'
    p.scriptFailed()
    p.fire('vite:preloadError')
    expect(p.reload).not.toHaveBeenCalled()
    p.fire('load')
    p.timers.forEach((run) => run())
    expect(storage.has('kutup-reload:b1')).toBe(false)
  })

  it('ignores other origins, and reloads on a failed preload', () => {
    const p = page()
    reloadGuard(p.win, 'b2')
    p.scriptFailed('https://cdn.example/x.js')
    expect(p.reload).not.toHaveBeenCalled()
    p.fire('vite:preloadError')
    expect(p.reload).toHaveBeenCalledTimes(1)
  })

  it('is a flag per build', () => {
    const p = page(new Map([['kutup-reload:old', '1']]))
    reloadGuard(p.win, 'new')
    p.scriptFailed()
    expect(p.reload).toHaveBeenCalledTimes(1)
  })

  it('inlines as a self-contained script', () => {
    const script = reloadGuardScript('b3')
    expect(script).toContain('kutup-reload:')
    expect(script).toMatch(/\(window, "b3"\);$/)
    // It parses on its own.
    expect(() => new Script(script)).not.toThrow()
  })
})
