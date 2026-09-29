import { expect, test, type BrowserContext, type Page } from '@playwright/test'
import { ADMIN_EMAIL, appUrl, newAccount, registerAccount, signInAsAdmin } from '../fixtures/apps'

test.describe.serial('administration', () => {
  let context: BrowserContext
  let page: Page

  test.beforeAll(async ({ browser }) => {
    context = await browser.newContext()
    await signInAsAdmin(context)
    page = await context.newPage()
  })

  test.afterAll(async () => {
    await context.close()
  })

  async function openUser(email: string) {
    await page.goto(appUrl('account', '/admin/users'))
    await page.getByPlaceholder('Search by email or username').fill(email)
    await page.getByRole('row').filter({ hasText: email }).first().click()
    await page.waitForURL(/\/admin\/users\/[0-9a-f-]{36}$/)
  }

  /** Creates an account awaiting its first sign-in; returns its email. */
  async function createUser(prefix: string): Promise<string> {
    const person = newAccount(prefix, 'unused')
    await page.goto(appUrl('account', '/admin/users/new'))
    await page.getByLabel('Email', { exact: true }).fill(person.email)
    await page.getByLabel('Username', { exact: true }).fill(person.username)
    await page.getByRole('button', { name: 'Create user' }).click()
    await expect(page.getByRole('heading', { name: 'User created' })).toBeVisible({ timeout: 30_000 })
    await page.getByRole('button', { name: 'Done' }).click()
    return person.email
  }

  async function confirm(submit: string, phrase?: string) {
    const dialog = page.getByRole('alertdialog')
    if (phrase) {
      await expect(dialog.getByRole('button', { name: submit, exact: true })).toBeDisabled()
      await dialog.getByRole('textbox').fill(phrase)
    }
    await dialog.getByRole('button', { name: submit, exact: true }).click()
    await expect(dialog).toBeHidden({ timeout: 15_000 })
  }

  test('the users page shows the server at a glance', async () => {
    await page.goto(appUrl('account', '/admin/users'))
    for (const stat of ['Users', 'Storage used', 'Files']) await expect(page.getByText(stat, { exact: true }).first()).toBeVisible()
    await expect(page.getByRole('row').filter({ hasText: ADMIN_EMAIL })).toBeVisible()
  })

  test('the break-glass administrator cannot be disabled, demoted, wiped or deleted', async () => {
    await openUser(ADMIN_EMAIL)
    await expect(page.getByText('Break-glass admin').first()).toBeVisible()
    for (const action of ['Disable account', 'Remove administrator', 'Wipe account', 'Delete account']) {
      await expect(page.getByRole('button', { name: action, exact: true })).toBeDisabled()
    }
  })

  test('an administrator can create, promote, demote and delete a user', async () => {
    const email = await createUser('e2eadmin')
    await openUser(email)
    await page.getByRole('button', { name: 'Make administrator', exact: true }).click()
    await confirm('Make administrator')
    await expect(page.getByRole('button', { name: 'Remove administrator', exact: true })).toBeEnabled({ timeout: 15_000 })
    await page.getByRole('button', { name: 'Remove administrator', exact: true }).click()
    await confirm('Remove administrator')
    await expect(page.getByRole('button', { name: 'Make administrator', exact: true })).toBeEnabled({ timeout: 15_000 })

    await page.getByRole('button', { name: 'Delete account', exact: true }).click()
    await confirm('Delete account', email)
    await page.waitForURL(/\/admin\/users$/)
    await page.getByPlaceholder('Search by email or username').fill(email)
    await expect(page.getByRole('row').filter({ hasText: email })).toHaveCount(0)

    await page.goto(appUrl('account', '/admin/activity'))
    await expect(page.getByText(new RegExp(`created ${email.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`)).first()).toBeVisible({ timeout: 15_000 })
    await expect(page.getByText(/deleted/).first()).toBeVisible()
  })

  test('an account awaiting its first sign-in gets a new temporary password', async () => {
    const email = await createUser('e2erotate')
    await openUser(email)
    await page.getByRole('button', { name: 'New temporary password', exact: true }).click()
    await confirm('New temporary password')
    await expect(page.getByRole('button', { name: 'Copy' }).first()).toBeVisible({ timeout: 15_000 })
    await page.goto(appUrl('account', '/admin/activity'))
    await expect(page.getByText(/replaced the temporary password of/).first()).toBeVisible({ timeout: 15_000 })

    await openUser(email)
    await page.getByRole('button', { name: 'Delete account', exact: true }).click()
    await confirm('Delete account', email)
    await page.waitForURL(/\/admin\/users$/)
  })

  test('wiping a locked-out account starts it over with a temporary password', async ({ browser }) => {
    test.slow()
    const person = newAccount('e2ewipe', 'Deneme123*WipedAccountPassword')
    const own = await browser.newContext()
    await registerAccount(own, person)
    await own.close()

    await openUser(person.email)
    await page.getByRole('button', { name: 'Wipe account', exact: true }).click()
    await confirm('Wipe account', person.email)
    const copy = page.getByRole('button', { name: 'Copy' }).first()
    await expect(copy).toBeVisible({ timeout: 15_000 })
    const temporary = (await copy.locator('xpath=preceding-sibling::*[1]').textContent())?.trim()
    expect(temporary).toBeTruthy()
    await page.goto(appUrl('account', '/admin/activity'))
    await expect(page.getByText(/wiped/).first()).toBeVisible({ timeout: 15_000 })

    // The old password is gone; the temporary one leads to a fresh setup.
    const fresh = await browser.newContext()
    const signIn = await fresh.newPage()
    for (const [password, outcome] of [
      [person.password, 'failed'],
      [temporary!, 'setup'],
    ] as const) {
      await signIn.goto(appUrl('account', '/login'))
      await signIn.getByLabel('Email', { exact: true }).fill(person.email)
      await signIn.getByLabel('Password', { exact: true }).fill(password)
      await signIn.getByRole('button', { name: 'Sign in' }).click()
      if (outcome === 'failed') await expect(signIn.getByRole('alert').filter({ hasText: 'Sign-in failed' })).toBeVisible({ timeout: 60_000 })
      else await expect(signIn.getByRole('heading', { name: 'Finish setting up your account' })).toBeVisible({ timeout: 60_000 })
    }
    await fresh.close()

    await openUser(person.email)
    await page.getByRole('button', { name: 'Delete account', exact: true }).click()
    await confirm('Delete account', person.email)
    await page.waitForURL(/\/admin\/users$/)
  })

  test('server settings open for the administrator', async () => {
    await page.goto(appUrl('account', '/admin/settings'))
    await expect(page.getByRole('heading', { name: 'Server settings' })).toBeVisible()
    await expect(page.getByText('Open registration').first()).toBeVisible()
  })
})
