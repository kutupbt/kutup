import { expect, test, type Page } from '@playwright/test'
import { appUrl, finishNewKeys, newAccount, signInAsAdmin } from '../fixtures/apps'

// Registration modes and referral codes (docs/plans/registration-codes.md):
// an administrator closes registration to codes, makes one, and a new person
// signs up with its link; a wrong code gets the one message; the code then
// shows its use. The mode is put back to "on" for the other specs.

const PASSWORD = 'Deneme123*ReferralCodes'
// Unique per run: codes stay on the server between runs.
const NOTE = `spec 155 ${Date.now().toString(36)}`

async function setMode(page: Page, label: 'Open to anyone' | 'With a referral code' | 'Closed') {
  await page.goto(appUrl('account', '/admin/settings'))
  await page.getByRole('combobox', { name: 'Registration' }).click()
  await page.getByRole('option', { name: label }).click()
  await page.getByRole('button', { name: 'Save' }).click()
  await expect(page.getByText('Settings saved').first()).toBeVisible({ timeout: 30_000 })
}

test('registration codes: closed to codes, a code made once, a sign-up through its link, its use shown', async ({ browser }) => {
  test.slow()
  const adminContext = await browser.newContext()
  await adminContext.grantPermissions(['clipboard-read', 'clipboard-write'])
  await signInAsAdmin(adminContext)
  const admin = await adminContext.newPage()
  try {
    await setMode(admin, 'With a referral code')

    // A code for one person, shown once, with its sign-up link.
    await admin.goto(appUrl('account', '/admin/codes'))
    await admin.getByRole('button', { name: 'New code' }).click()
    const dialog = admin.getByRole('dialog', { name: 'New referral code' })
    await dialog.getByLabel('Note').fill(NOTE)
    await dialog.getByRole('button', { name: 'Make code' }).click()
    const made = admin.getByRole('dialog', { name: 'Your referral code' })
    const code = ((await made.getByLabel('The referral code').textContent()) ?? '').trim()
    expect(code).toMatch(/^[0-9A-HJKMNP-TV-Z]{5}(-[0-9A-HJKMNP-TV-Z]{5}){3}$/)
    await made.getByRole('button', { name: 'Copy sign-up link' }).click()
    const link = await admin.evaluate(() => navigator.clipboard.readText())
    expect(link).toContain(`/register#code=${code}`)
    await made.getByRole('button', { name: 'Done' }).click()
    // Afterwards only its last four characters.
    await expect(admin.getByText(code)).toHaveCount(0)
    const hint = `…${code.replace(/-/g, '').slice(-4)}`
    await expect(admin.getByRole('row').filter({ hasText: NOTE }).getByText(hint, { exact: true })).toBeVisible()

    // Without a code: the field is required. A wrong one: the one message.
    const visitor = await browser.newContext()
    const signup = await visitor.newPage()
    await signup.goto(appUrl('account', '/register'))
    const account = newAccount('ref155', PASSWORD)
    await signup.getByLabel('Username', { exact: true }).fill(account.username)
    await signup.getByLabel('Referral code').fill('00000-00000-00000-00000')
    await signup.getByLabel('New password', { exact: true }).fill(PASSWORD)
    await signup.getByLabel('Repeat password', { exact: true }).fill(PASSWORD)
    await signup.getByRole('button', { name: 'Continue' }).click()
    await expect(signup.getByText('This referral code cannot be used.')).toBeVisible({ timeout: 30_000 })

    // Through the link: the code is filled in, and the account is made.
    await signup.goto(link)
    await expect(signup.getByLabel('Referral code')).toHaveValue(code)
    await signup.getByLabel('Username', { exact: true }).fill(account.username)
    await finishNewKeys(signup, PASSWORD)
    await visitor.close()

    // The code shows its one use, and who used it.
    await admin.goto(appUrl('account', '/admin/codes'))
    const row = admin.getByRole('row').filter({ hasText: NOTE })
    await expect(row.getByText('Used up')).toBeVisible({ timeout: 30_000 })
    await row.getByRole('button', { name: /Who used the code/ }).click()
    await expect(admin.getByRole('dialog').getByRole('link', { name: account.username })).toBeVisible()
  } finally {
    await setMode(admin, 'Open to anyone')
    await adminContext.close()
  }
})
