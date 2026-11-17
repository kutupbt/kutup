// Playwright's `test` and `expect` for every spec, with one addition: each
// page's Content-Security-Policy violations (enforced or report-only, in the
// page and its frames) are recorded per test, through the browser's
// `securitypolicyviolation` event (docs/content-security-policy.md). With
// E2E_CSP_STRICT=1 a test that saw any fails; otherwise they are attached
// to the test's report and the test goes on. Specs import from here, not
// from '@playwright/test'.
import { test as base, type Browser, type BrowserContext } from '@playwright/test'

export * from '@playwright/test'

/** One violation, as the page reported it (no query strings). */
export interface CspViolation {
  page: string
  directive: string
  blocked: string
  disposition: string
}

const STRICT = process.env.E2E_CSP_STRICT === '1'
const BINDING = '__kutupCspViolation'

// The page side: report each violation once to the binding below.
const LISTENER = `(() => {
  const seen = new Set()
  const strip = (url) => { try { const u = new URL(url); return u.origin === 'null' ? u.protocol : u.origin + u.pathname } catch { return String(url || '') } }
  document.addEventListener('securitypolicyviolation', (event) => {
    const record = {
      page: strip(event.documentURI),
      directive: event.effectiveDirective || event.violatedDirective,
      blocked: strip(event.blockedURI),
      disposition: event.disposition,
    }
    const key = JSON.stringify(record)
    if (seen.has(key)) return
    seen.add(key)
    const send = globalThis['${BINDING}']
    if (typeof send === 'function') send(record).catch(() => {})
  }, true)
})()`

/** What the current test has seen; the worker runs one test at a time. */
let current: CspViolation[] = []
const watched = new WeakSet<BrowserContext>()

async function watch(context: BrowserContext): Promise<void> {
  if (watched.has(context)) return
  watched.add(context)
  await context.exposeBinding(BINDING, (_source, record: CspViolation) => {
    current.push(record)
  })
  await context.addInitScript({ content: LISTENER })
}

export const test = base.extend<{ cspViolations: CspViolation[] }, { cspWatch: void }>({
  // The default context too, however Playwright makes it.
  context: async ({ context }, use) => {
    await watch(context)
    await use(context)
  },
  // Every context the worker's browser makes, by the `context` fixture or by
  // a spec's own browser.newContext(), is watched.
  cspWatch: [
    async ({ browser }: { browser: Browser }, use) => {
      const newContext = browser.newContext.bind(browser)
      browser.newContext = async (...args: Parameters<Browser['newContext']>) => {
        const context = await newContext(...args)
        await watch(context)
        return context
      }
      await use()
      browser.newContext = newContext
    },
    { scope: 'worker', auto: true },
  ],
  cspViolations: [
    async ({ cspWatch: _ }, use, testInfo) => {
      current = []
      const seen = current
      await use(seen)
      if (seen.length === 0) return
      await testInfo.attach('csp-violations', {
        body: JSON.stringify(seen, null, 2),
        contentType: 'application/json',
      })
      if (STRICT) {
        const list = seen.map((v) => `${v.disposition} ${v.directive} ${v.blocked} on ${v.page}`).join('\n')
        throw new Error(`Content-Security-Policy violations (E2E_CSP_STRICT=1):\n${list}`)
      }
    },
    { auto: true },
  ],
})
