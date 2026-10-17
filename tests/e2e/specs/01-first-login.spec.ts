import { expect, test } from '@playwright/test'
import { ADMIN_USERNAME, appUrl, finishNewKeys, newAccount, signInAsAdmin, submitThroughRateLimit } from '../fixtures/apps'

const PASSWORD = 'Deneme123*FirstLoginPassword'

test('an account an administrator created finishes setup at its first sign-in', async ({ browser }) => {
  test.slow()
  const person = newAccount('firstlogin', PASSWORD)

  // The administrator creates the account; only a temporary password exists.
  const adminContext = await browser.newContext()
  await signInAsAdmin(adminContext)
  const admin = await adminContext.newPage()
  await admin.goto(appUrl('account', '/admin/users/new'))
  await admin.getByLabel('Username', { exact: true }).fill(person.username)
  await admin.getByRole('button', { name: 'Create user' }).click()
  await expect(admin.getByRole('heading', { name: 'User created' })).toBeVisible({ timeout: 30_000 })
  const temporary = (await admin.getByRole('button', { name: 'Copy' }).locator('xpath=preceding-sibling::*[1]').textContent())?.trim()
  expect(temporary).toBeTruthy()
  await adminContext.close()

  // The person signs in with it and makes their own keys on their device.
  const context = await browser.newContext()
  const page = await context.newPage()
  await page.goto(appUrl('account', '/login'))
  await page.getByLabel('Username', { exact: true }).fill(person.username)
  await page.getByLabel('Password', { exact: true }).fill(temporary!)
  // Through the edge's sign-in limit, as every sign-in of the suite.
  await submitThroughRateLimit(page, 'Sign in', page.getByRole('heading', { name: 'Finish setting up your account' }))
  await finishNewKeys(page, PASSWORD)

  // The temporary password is spent; their own password signs them in.
  await context.clearCookies()
  await page.evaluate(() => localStorage.clear())
  for (const [password, outcome] of [
    [temporary!, 'Sign-in failed'],
    [PASSWORD, 'Welcome'],
  ] as const) {
    await page.goto(appUrl('account', '/login'))
    await page.getByLabel('Username', { exact: true }).fill(person.username)
    await page.getByLabel('Password', { exact: true }).fill(password)
    const done =
      outcome === 'Welcome' ? page.getByRole('heading', { name: /^Welcome/ }) : page.getByRole('alert').filter({ hasText: outcome })
    await submitThroughRateLimit(page, 'Sign in', done)
  }

  // Drive opens as the person, with an empty My files.
  await page.goto(appUrl('drive', '/'))
  await expect(page.getByRole('button', { name: 'New' }).first()).toBeVisible({ timeout: 120_000 })
  await context.close()
})

test('sign-in refuses a wrong password and an unknown name alike', async ({ browser }) => {
  const context = await browser.newContext()
  const page = await context.newPage()
  for (const name of [ADMIN_USERNAME, `nobody${Date.now()}`]) {
    await page.goto(appUrl('account', '/login'))
    await page.getByLabel('Username', { exact: true }).fill(name)
    await page.getByLabel('Password', { exact: true }).fill('Not*TheRightPassword123')
    // The same message either way: sign-in does not reveal which accounts exist.
    await submitThroughRateLimit(page, 'Sign in', page.getByRole('alert').filter({ hasText: 'Sign-in failed. Check your username and password.' }))
    await expect(page).toHaveURL(/\/login/)
  }
  await context.close()
})
