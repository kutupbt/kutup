/**
 * What the page needs of its window; a parameter so tests can hand in fakes.
 * Written without imports or outer names: the build inlines this function's
 * source in each app's index.html ([`reloadGuardScript`]).
 */
export interface GuardWindow {
  document: Document
  sessionStorage: Pick<Storage, 'getItem' | 'setItem' | 'removeItem'>
  localStorage: Pick<Storage, 'getItem'>
  navigator: { language: string }
  location: { origin: string; reload(): void }
  addEventListener(type: string, listener: (event: Event) => void, capture?: boolean): void
  setTimeout(handler: () => void, ms: number): unknown
}

/**
 * While an app page is still blank, a script or stylesheet of its own that
 * fails to load (or a failed preload, Vite's `vite:preloadError`) reloads it,
 * once per page load: a sessionStorage flag keyed to the build remembers the
 * reload. If the page fails again after it, a plain error page offers a
 * Reload button instead; there is no loop. The flag clears once the page has
 * drawn. Chrome aborts requests in flight when the device's network changes
 * (`net::ERR_NETWORK_CHANGED`), which leaves a page blank otherwise.
 *
 * A page that finds itself older than the code it talks to (the service
 * worker's stream protocol, @kutup/files stream/page.ts) dispatches
 * [`RELOAD_NEEDED_EVENT`] on the window: the same page then offers its
 * Reload button, saying Kutup was updated, whatever the page shows.
 */
export function reloadGuard(win: GuardWindow, build: string): void {
  const key = `kutup.ui.reload:${build}`
  let handled = false
  const root = () => win.document.getElementById('root')
  const blank = () => {
    const element = root()
    return !element || element.childElementCount === 0
  }
  const tried = () => {
    try {
      return win.sessionStorage.getItem(key) !== null
    } catch {
      // Without storage a reload could not be counted: no reload at all.
      return true
    }
  }

  // The words are here, not in the app's translations: the app's bundle is
  // what failed to load.
  function showError(updated = false) {
    let language = ''
    try {
      language = win.localStorage.getItem('kutup.ui.language') ?? ''
    } catch {
      language = ''
    }
    const tr = (language || win.navigator.language).toLowerCase().startsWith('tr')
    const text = updated
      ? tr
        ? { title: 'Kutup güncellendi', body: 'Bu sayfa Kutup’un yeni sürümünden eski. Sürdürmek için yeniden yükleyin.', reload: 'Yeniden yükle' }
        : { title: 'Kutup was updated', body: 'This page is older than the new version of Kutup. Reload to go on.', reload: 'Reload' }
      : tr
        ? { title: 'Kutup yüklenemedi', body: 'Bu sayfanın bir kısmı gelmedi; ağınız değişmiş olabilir. Bağlantınızı denetleyip yeniden yükleyin.', reload: 'Yeniden yükle' }
        : { title: 'Kutup could not load', body: 'Part of this page did not arrive, perhaps because your network changed. Check your connection and reload.', reload: 'Reload' }
    const render = () => {
      const doc = win.document
      const host = root() ?? doc.body
      const page = doc.createElement('main')
      page.setAttribute('role', 'alert')
      page.style.cssText =
        'min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:12px;padding:24px;text-align:center;font-family:system-ui,sans-serif;background:Canvas;color:CanvasText'
      const title = doc.createElement('h1')
      title.textContent = text.title
      title.style.cssText = 'margin:0;font-size:20px'
      const body = doc.createElement('p')
      body.textContent = text.body
      body.style.cssText = 'margin:0;max-width:28rem;opacity:.8'
      const button = doc.createElement('button')
      button.type = 'button'
      button.textContent = text.reload
      button.style.cssText = 'padding:8px 16px;border-radius:6px;border:1px solid currentColor;background:transparent;color:inherit;font:inherit;cursor:pointer'
      button.addEventListener('click', () => {
        // A reload the person asks for may reload once more by itself.
        try {
          win.sessionStorage.removeItem(key)
        } catch {
          // Nothing to clear.
        }
        win.location.reload()
      })
      page.append(title, body, button)
      host.replaceChildren(page)
    }
    if (win.document.readyState === 'loading') win.document.addEventListener('DOMContentLoaded', render)
    else render()
  }

  function failed() {
    if (handled || !blank()) return
    handled = true
    if (tried()) {
      showError()
      return
    }
    try {
      win.sessionStorage.setItem(key, '1')
    } catch {
      showError()
      return
    }
    win.location.reload()
  }

  win.addEventListener(
    'error',
    (event) => {
      const element = event.target as (HTMLElement & { src?: string; href?: string }) | null
      const url = element?.tagName === 'SCRIPT' ? element.src : element?.tagName === 'LINK' ? element.href : ''
      if (url && url.startsWith(`${win.location.origin}/`)) failed()
    },
    true,
  )
  win.addEventListener('vite:preloadError', () => failed())
  // The literal of RELOAD_NEEDED_EVENT: this function's source is inlined alone.
  win.addEventListener('kutup:reload-needed', () => {
    if (handled) return
    handled = true
    showError(true)
  })
  win.addEventListener('load', () => {
    win.setTimeout(() => {
      if (!blank()) {
        try {
          win.sessionStorage.removeItem(key)
        } catch {
          // Nothing to clear.
        }
      }
    }, 5000)
  })
}

/** What a page dispatches on its window when it must reload to talk to newer code. */
export const RELOAD_NEEDED_EVENT = 'kutup:reload-needed'

/** The inline `<script>` body for an app built as `build`. */
export function reloadGuardScript(build: string): string {
  return `(${reloadGuard.toString()})(window, ${JSON.stringify(build)});`
}
