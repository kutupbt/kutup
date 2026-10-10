import { expect, test } from '@playwright/test'
import { appOrigin, appUrl, newAccount, registerAccount } from '../fixtures/apps'

const PASSWORD = 'Deneme123*SignInLinkPassword'

// A sign-in link (a session fork: /login#selector=…&sk=…&state=…) signs in
// only the tab that asked for it. Someone else's link, sent to a victim,
// must not sign the victim's browser in to the sender's account (login
// CSRF): whatever they then save would go to the attacker.
test("a sign-in link made for someone else's tab signs nobody in", async ({ browser }) => {
  test.slow()
  const alice = newAccount('forkalice', PASSWORD)
  const attacker = await browser.newContext()
  await registerAccount(attacker, alice)

  // Alice's account app mints a link to Drive for a request it was never
  // sent; it is caught before Drive can use it.
  const page = await attacker.newPage()
  await page.route(`${appOrigin('drive')}/login*`, (route) => route.fulfill({ contentType: 'text/html', body: '<!doctype html><title>caught</title>' }))
  await page.goto(appUrl('account', '/authorize?app=drive&state=minted-by-alice'))
  await page.waitForURL((url) => url.origin === appOrigin('drive') && url.pathname === '/login', { timeout: 60_000 })
  const link = page.url()
  expect(new URL(link).hash).toContain('selector=')
  await attacker.close()

  // Someone with no session opens it: Drive does not take it, and asks
  // them to sign in as themselves.
  const victim = await browser.newContext()
  const tab = await victim.newPage()
  await tab.goto(link)
  await tab.waitForURL((url) => url.origin === appOrigin('account') && url.pathname === '/login', { timeout: 60_000 })
  await expect(tab.getByLabel('Email', { exact: true })).toBeVisible()
  await victim.close()
})
