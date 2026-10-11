import { expect, test, type APIRequestContext, type BrowserContext } from '@playwright/test'
import { appUrl, newAccount, registerAccount } from '../fixtures/apps'

// A fetch cut off mid-load (Chrome's net::ERR_NETWORK_CHANGED when the
// device's network changes) costs one more try, not a stuck page: lazy
// chunks and the WASM runtimes load again under a fresh URL, the key worker
// runs again, and a page whose own bundle failed reloads itself once, then
// shows an error page with Reload rather than reloading in a loop.

const PASSWORD = 'Deneme123*LoadRetriesPassword'

/** Aborts the first request whose URL matches `pattern`, as a network change does; returns how many there were. */
async function cutFirst(context: BrowserContext, pattern: RegExp): Promise<() => number> {
  let seen = 0
  await context.route(pattern, async (route) => {
    seen++
    if (seen === 1) await route.abort('internetdisconnected')
    else await route.continue()
  })
  return () => seen
}

/** The Mail page's own bundle, as its index.html names it. */
async function mailEntry(request: APIRequestContext): Promise<RegExp> {
  const html = await (await request.get(appUrl('mail'))).text()
  expect(html, 'the reload guard is in the page').toContain('kutup-reload:')
  const src = /<script type="module"[^>]*src="([^"]+)"/.exec(html)?.[1]
  if (!src) throw new Error('no entry script in mail/index.html')
  return new RegExp(`${src.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`)
}

test('registration survives cut-off chunk, worker and WASM fetches', async ({ browser }) => {
  test.slow()
  const context = await browser.newContext()
  const sodium = await cutFirst(context, /\/assets\/libsodium-wrappers[^/]*\.js(\?|$)/)
  // zxcvbn's chunk is named for its entry file, lib/main.js.
  const zxcvbn = await cutFirst(context, /account\.[^/]+\/assets\/main-[^/]*\.js(\?|$)/)
  const wasm = await cutFirst(context, /\/crypto-wasm\/[^/]+\/kutup_crypto_wasm\.js(\?|$)/)
  await registerAccount(context, newAccount('lrreg', PASSWORD))
  // Each was cut once and fetched again.
  for (const [name, count] of [['libsodium', sodium()], ['zxcvbn', zxcvbn()], ['crypto wasm', wasm()]] as const) {
    expect(count, `${name} fetched again after the cut`).toBeGreaterThanOrEqual(2)
  }
  await context.close()
})

test('an app whose own bundle was cut off reloads itself once', async ({ browser, request }) => {
  test.slow()
  const context = await browser.newContext()
  await registerAccount(context, newAccount('lrapp', PASSWORD))
  const entry = await cutFirst(context, await mailEntry(request))
  const page = await context.newPage()
  await page.goto(appUrl('mail'))
  await expect(page.getByRole('heading', { name: 'Inbox' })).toBeVisible({ timeout: 120_000 })
  expect(entry()).toBeGreaterThanOrEqual(2)
  // Once per load: the flag that stops a loop clears after the page drew.
  await expect.poll(() => page.evaluate(() => Object.keys(sessionStorage).filter((k) => k.startsWith('kutup-reload:')).length), { timeout: 15_000 }).toBe(0)
  await context.close()
})

test('a bundle that keeps failing does not reload in a loop', async ({ browser, request }) => {
  const context = await browser.newContext()
  let loads = 0
  await context.route(await mailEntry(request), (route) => route.abort('internetdisconnected'))
  const page = await context.newPage()
  // A reload cuts the first load short before its load event: count navigations.
  page.on('framenavigated', (frame) => {
    if (frame === page.mainFrame()) loads++
  })
  await page.goto(appUrl('mail'))
  await page.waitForTimeout(8_000)
  // The first load and one reload, then an error page with Reload.
  expect(loads).toBe(2)
  await expect(page.getByRole('alert').getByRole('heading', { name: 'Kutup could not load' })).toBeVisible()
  await expect(page.getByRole('button', { name: 'Reload' })).toBeVisible()
  await context.close()
})
