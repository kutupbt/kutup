import { expect, test, type Page } from '@playwright/test'
import { appUrl, newAccount, registerAccount } from '../fixtures/apps'

// Recipients (docs/plans/mail-parity.md, P4), as Proton's: a contact group
// is offered while typing and adds its members; a recipient is dragged
// from To to Cc.

const PASSWORD = 'Deneme123*MailRecipientGroupsPassword'

async function addContact(page: Page, first: string, last: string, email: string) {
  await page.getByRole('button', { name: 'New contact' }).first().click()
  const editor = page.getByRole('dialog', { name: 'New contact' })
  await editor.getByLabel('First name').fill(first)
  await editor.getByLabel('Last name').fill(last)
  await editor.getByLabel('Email address').fill(email)
  await editor.getByRole('button', { name: 'Save' }).click()
  await expect(editor).toHaveCount(0, { timeout: 30_000 })
  await expect(page.getByRole('article', { name: `${first} ${last}` })).toBeVisible({ timeout: 30_000 })
}

test('a contact group adds its members; a recipient moves from To to Cc', async ({ browser }) => {
  test.slow()
  const context = await browser.newContext({ viewport: { width: 1400, height: 900 } })
  await registerAccount(context, newAccount('rgalice', PASSWORD))
  const page = await context.newPage()
  await page.goto(appUrl('contacts'))
  await expect(page.getByText('No contacts yet')).toBeVisible({ timeout: 120_000 })
  const tag = Date.now().toString(36)
  await addContact(page, 'Ayşe', 'Yılmaz', `ayse-${tag}@example.org`)
  await addContact(page, 'Ali', 'Veli', `ali-${tag}@example.org`)
  // The group "Ekip", with both in it.
  await page.getByRole('button', { name: 'New group' }).click()
  const group = page.getByRole('dialog', { name: 'New group' })
  await group.getByLabel('Name').fill('Ekip')
  await group.getByRole('button', { name: 'Save' }).click()
  await expect(page.getByText('Group created')).toBeVisible({ timeout: 30_000 })
  for (const name of ['Ayşe Yılmaz', 'Ali Veli']) {
    await page.getByRole('article', { name }).getByRole('button', { name: 'Edit' }).click()
    const edit = page.getByRole('dialog', { name: 'Edit contact' })
    await edit.getByRole('checkbox', { name: 'Ekip' }).check()
    await edit.getByRole('button', { name: 'Save' }).click()
    await expect(edit).toHaveCount(0, { timeout: 30_000 })
  }

  const mail = await context.newPage()
  await mail.goto(appUrl('mail'))
  await expect(mail.getByRole('heading', { name: 'Inbox' })).toBeVisible({ timeout: 120_000 })
  await mail.getByRole('button', { name: 'New message' }).first().click()
  const composer = mail.getByRole('dialog', { name: 'New message' })
  const to = composer.getByRole('combobox', { name: 'To' })
  await to.fill('Eki')
  const option = mail.getByRole('option', { name: /Ekip/ })
  await expect(option).toContainText('Contact group · 2 members', { timeout: 30_000 })
  await option.click()
  // Both members, as recipients of their own.
  const removeAyse = composer.getByRole('button', { name: `Remove ayse-${tag}@example.org` })
  const removeAli = composer.getByRole('button', { name: `Remove ali-${tag}@example.org` })
  await expect(removeAyse).toBeVisible()
  await expect(removeAli).toBeVisible()

  // Ali dragged from To to Cc.
  await composer.getByRole('button', { name: 'Cc / Bcc' }).click()
  const cc = composer.getByRole('combobox', { name: 'Cc' })
  await composer.getByTitle(`ali-${tag}@example.org`).dragTo(cc)
  const ccField = composer.locator('div').filter({ has: cc }).last()
  await expect(ccField.getByTitle(`ali-${tag}@example.org`)).toBeVisible({ timeout: 10_000 })
  const toField = composer.locator('div').filter({ has: to }).last()
  await expect(toField.getByTitle(`ali-${tag}@example.org`)).toHaveCount(0)
  await expect(toField.getByTitle(`ayse-${tag}@example.org`)).toBeVisible()
  await context.close()
})
