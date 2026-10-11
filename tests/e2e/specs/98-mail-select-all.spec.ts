import { expect, test } from '@playwright/test'
import { apiUrl, appUrl, newAccount, registerAccount } from '../fixtures/apps'
import { seedDrafts } from '../fixtures/mail'

// Select all across pages (docs/plans/mail-parity.md, P3), as Proton's:
// with a whole page checked, "Select all N in <place>"; actions then go to
// every message of the place, each asked first.

const PASSWORD = 'Deneme123*MailSelectAllPassword'

test('select all: the banner, a label and read state for the whole place', async ({ browser }) => {
  test.slow()
  const context = await browser.newContext({ viewport: { width: 1400, height: 900 } })
  await registerAccount(context, newAccount('selall', PASSWORD))
  const mail = await context.newPage()
  await mail.goto(appUrl('mail'))
  await expect(mail.getByRole('heading', { name: 'Inbox' })).toBeVisible({ timeout: 120_000 })
  const tag = Date.now().toString(36)
  const authorization = await seedDrafts(mail, `Hepsi ${tag}`, 50)
  const nav = mail.getByRole('navigation').filter({ has: mail.getByRole('button', { name: 'New label' }) })
  await nav.getByRole('button', { name: 'New label' }).click()
  const dialog = mail.getByRole('dialog', { name: 'New label' })
  await dialog.getByLabel('Label name').fill(`Toplu ${tag}`)
  await dialog.getByRole('button', { name: 'Save' }).click()
  await expect(nav.getByRole('link', { name: `Toplu ${tag}` })).toBeVisible({ timeout: 30_000 })

  await mail.getByRole('link', { name: /^Drafts( \d+)?$/ }).click()
  const rows = mail.getByRole('link', { name: new RegExp(`Hepsi ${tag}`) })
  await expect(rows).toHaveCount(50, { timeout: 30_000 })
  // Part of a page: no banner; the whole page: Proton's banner.
  const banner = mail.getByRole('status').filter({ hasText: 'You selected' })
  await mail.getByRole('checkbox', { name: new RegExp(`Select “Hepsi ${tag}`) }).first().check({ force: true })
  await expect(banner).toHaveCount(0)
  await mail.getByRole('checkbox', { name: 'Select all', exact: true }).check()
  await expect(banner).toContainText('You selected 50 conversations.')
  await banner.getByRole('button', { name: 'Select all 51 in Drafts' }).click()
  await expect(banner).toContainText('You selected 51 conversations.')
  await expect(mail.getByRole('region', { name: 'Selection pane' })).toContainText('You selected 51 conversations in Drafts')

  // Label as: asked first, then on all 51, on both pages.
  await mail.getByRole('button', { name: 'Label as' }).click()
  await mail.getByRole('list', { name: 'Label as' }).getByRole('button', { name: `Toplu ${tag}` }).click()
  await mail.getByRole('button', { name: 'Apply' }).click()
  const confirm = mail.getByRole('dialog', { name: 'Action all conversations' })
  await expect(confirm).toContainText('51 conversations will be labelled as:')
  await expect(confirm).toContainText(`Toplu ${tag}`)
  await confirm.getByRole('button', { name: 'OK' }).click()
  await expect(confirm).toHaveCount(0)
  await expect(banner).toHaveCount(0, { timeout: 30_000 })
  await nav.getByRole('link', { name: `Toplu ${tag}` }).click()
  await expect(mail.getByRole('button', { name: 'Page 1 of 2' })).toBeVisible({ timeout: 30_000 })

  // In the label: all 51 unread, with Cancel first doing nothing.
  await mail.getByRole('checkbox', { name: 'Select all', exact: true }).check()
  await banner.getByRole('button', { name: /^Select all 51 in / }).click()
  await mail.getByRole('button', { name: 'Mark as unread' }).click()
  let mark = mail.getByRole('dialog', { name: 'Mark conversations as unread' })
  await expect(mark).toContainText('51 conversations will be marked as unread.')
  await mark.getByRole('button', { name: 'Cancel' }).click()
  await expect(mark).toHaveCount(0)
  await mail.getByRole('button', { name: 'Mark as unread' }).click()
  mark = mail.getByRole('dialog', { name: 'Mark conversations as unread' })
  await mark.getByRole('button', { name: 'Mark as unread' }).click()
  await expect(mark).toHaveCount(0)
  const label = new URL(mail.url()).pathname.split('/')[2]
  await expect
    .poll(async () => {
      const page = (await (await mail.request.get(apiUrl(`/mail/messages?folder=label:${label}&unread=true&page=0&limit=50`), { headers: { authorization } })).json()) as { total: number }
      return page.total
    })
    .toBe(51)

  // Unchecking a row ends select all.
  await mail.getByRole('checkbox', { name: 'Select all', exact: true }).check()
  await banner.getByRole('button', { name: /^Select all 51 in / }).click()
  await mail.getByRole('checkbox', { name: new RegExp(`Select “Hepsi ${tag}`) }).first().uncheck({ force: true })
  await expect(banner).toHaveCount(0)
  await context.close()
})
