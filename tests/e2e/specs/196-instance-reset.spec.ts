import { expect, test, type BrowserContext } from '../fixtures/test'
import { appUrl, newAccount, registerAccount } from '../fixtures/apps'

// A reset server (docs/plans/api-surface.md §5): the browser keeps what it
// stored for a server under that server's instance id. When the server
// answers with another one (a wipe), each app origin clears its storage,
// keeping only the anti-rollback anchors and the look, and the sign-in page
// says the server was reset. The test stack can't be wiped under a running
// spec, so the answers are given another id here: health's body and every
// API answer's X-Kutup-Instance header.

const PASSWORD = 'Deneme123*InstanceReset'
const RESET_ID = 'AAAAAAAAAAAAAAAAAAAAAA'

async function answerAsAnotherInstance(context: BrowserContext) {
  await context.route(/\/api\//, async (route) => {
    const response = await route.fetch()
    const headers = { ...response.headers() }
    if (headers['x-kutup-instance']) headers['x-kutup-instance'] = RESET_ID
    const url = new URL(route.request().url())
    if (url.pathname === '/api/health') {
      const body = (await response.json()) as Record<string, unknown>
      await route.fulfill({ response, headers, json: { ...body, instanceId: RESET_ID } })
      return
    }
    await route.fulfill({ response, headers })
  })
}

test('instance reset: a wiped server clears what each origin kept for it, but the anchors', async ({ browser }) => {
  test.slow()
  const account = newAccount('instance', PASSWORD)
  const context = await browser.newContext()
  await registerAccount(context, account)
  const drive = await context.newPage()
  await drive.goto(appUrl('drive', '/'))
  await expect(drive.getByRole('navigation').first()).toBeVisible({ timeout: 60_000 })
  // This origin keeps a session, the look, and (once it read any) the
  // account's records and its rollback guard.
  await expect.poll(() => drive.evaluate(() => localStorage.getItem('kutup.session') !== null), { timeout: 30_000 }).toBe(true)
  const before = await drive.evaluate(() => localStorage.getItem('kutup.instance'))
  expect(before).toBeTruthy()
  expect(before).not.toBe(RESET_ID)
  await drive.evaluate(() => {
    localStorage.setItem('kutup.ui.theme', 'dark')
    localStorage.setItem('kutup.account.manifestPins:x', 'pin')
  })

  // The server is now "another one": the next load clears Drive's origin,
  // which has no session left and asks the account app, whose origin
  // clears too and says why.
  await answerAsAnotherInstance(context)
  await drive.reload()
  await expect(drive).toHaveURL(/\/login/, { timeout: 60_000 })
  await expect(drive.getByText('This server was reset since you last used it here')).toBeVisible({ timeout: 30_000 })
  expect(await drive.evaluate(() => localStorage.getItem('kutup.session'))).toBeNull()
  expect(await drive.evaluate(() => localStorage.getItem('kutup.instance'))).toBe(RESET_ID)

  // Drive's origin, read from a page that runs no app (the service worker's
  // script): only the anchors and the look are left.
  const origin = await context.newPage()
  await origin.goto(appUrl('drive', '/kutup-sw.js'))
  const after = await origin.evaluate(async () => ({
    instance: localStorage.getItem('kutup.instance'),
    session: localStorage.getItem('kutup.session'),
    theme: localStorage.getItem('kutup.ui.theme'),
    pins: localStorage.getItem('kutup.account.manifestPins:x'),
    databases: (await indexedDB.databases()).map((db) => db.name ?? ''),
  }))
  expect(after.instance).toBe(RESET_ID)
  expect(after.session).toBeNull()
  expect(after.theme).toBe('dark')
  expect(after.pins).toBe('pin')
  expect(after.databases.filter((name) => name.startsWith('kutup') && name !== 'kutup.account.revisionsSeen')).toEqual([])
  await context.close()
})
