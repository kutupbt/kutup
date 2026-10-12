import { expect, test } from '@playwright/test'
import { appUrl, newAccount, registerAccount } from '../fixtures/apps'
import { seedDrafts } from '../fixtures/mail'

// Pages of the list (docs/plans/mail-parity.md, P3), as Proton's: previous,
// "page/pages" and next at the toolbar's end, numbered pages at the foot,
// the page in the address bar, the page size in Settings → General, and
// the selection pane beside the list.

const PASSWORD = 'Deneme123*MailPagingPassword'

test('the list pages as Proton: controls, address bar, page size, selection pane', async ({ browser }) => {
  test.slow()
  const context = await browser.newContext({ viewport: { width: 1400, height: 900 } })
  await registerAccount(context, newAccount('paging', PASSWORD))
  const mail = await context.newPage()
  await mail.goto(appUrl('mail'))
  await expect(mail.getByRole('heading', { name: 'Inbox' })).toBeVisible({ timeout: 120_000 })

  // 51 drafts.
  const tag = Date.now().toString(36)
  await seedDrafts(mail, `Sayfa ${tag}`, 50)

  await mail.getByRole('link', { name: /^Drafts( \d+)?$/ }).click()
  const rows = mail.getByRole('link', { name: new RegExp(`Sayfa ${tag}`) })
  await expect(rows).toHaveCount(50, { timeout: 30_000 })
  await expect(mail.getByRole('button', { name: 'Page 1 of 2' })).toHaveText('1/2')
  const pane = mail.getByRole('region', { name: 'Selection pane' })
  await expect(pane).toContainText('You have 51 conversations stored in this folder')
  const foot = mail.getByRole('navigation', { name: 'Pages' })
  await expect(foot.getByRole('button', { name: 'Go to page 1' })).toHaveAttribute('aria-current', 'page')

  // Next: the second page, in the address bar; next is off at the end.
  await mail.getByRole('button', { name: 'Next page', exact: true }).click()
  await expect(mail).toHaveURL(/[?&]page=2/)
  await expect(rows).toHaveCount(1)
  await expect(mail.getByRole('button', { name: 'Page 2 of 2' })).toBeVisible()
  await expect(mail.getByRole('button', { name: 'Next page', exact: true })).toBeDisabled()
  // A reload keeps the page.
  await mail.reload()
  await expect(rows).toHaveCount(1, { timeout: 60_000 })
  // Back from the foot; the dropdown picks a page too.
  await foot.getByRole('button', { name: 'Go to page 1' }).click()
  await expect(rows).toHaveCount(50)
  await expect(mail).not.toHaveURL(/page=/)
  await mail.getByRole('button', { name: 'Page 1 of 2' }).click()
  await mail.getByRole('menuitemradio', { name: 'Page 2' }).click()
  await expect(rows).toHaveCount(1)

  // Checked rows: the pane says how many, and clears them.
  await mail.getByRole('checkbox', { name: new RegExp(`Select “Sayfa ${tag}`) }).first().check({ force: true })
  await expect(pane).toContainText('You selected 1 conversation from this folder')
  await pane.getByRole('button', { name: 'Clear selection' }).click()
  await expect(pane).toContainText('You have 51 conversations stored in this folder')

  // A page of 100: one page, no foot.
  await mail.goto(appUrl('mail', '/settings/general'))
  await mail.getByRole('combobox', { name: 'Conversations per page' }).click()
  await mail.getByRole('option', { name: '100' }).click()
  await expect(mail.getByText('Preference saved.')).toBeVisible({ timeout: 30_000 })
  await mail.goto(appUrl('mail', '/drafts'))
  await expect(rows).toHaveCount(51, { timeout: 60_000 })
  await expect(mail.getByRole('button', { name: 'Page 1 of 1' })).toBeDisabled()
  await expect(mail.getByRole('navigation', { name: 'Pages' })).toHaveCount(0)
  await context.close()
})
