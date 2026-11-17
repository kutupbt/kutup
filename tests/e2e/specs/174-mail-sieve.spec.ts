import { readFile } from 'node:fs/promises'
import { expect, test } from '@playwright/test'
import { appUrl, newAccount, registerAccount } from '../fixtures/apps'

// Filters as Sieve (docs/plans/mail-filters.md, F4): a Proton-style script
// imported in Settings → Filters adds the filters Kutup can hold and names
// what it skipped; Export as Sieve downloads them in Proton's dialect.

const PASSWORD = 'Deneme123*MailSievePassword'

const SCRIPT = `require ["include", "environment", "variables", "relational", "comparator-i;ascii-numeric", "spamtest"];
require ["fileinto", "imap4flags"];
# Generated: Do not run this script on spam messages
if allof (environment :matches "vnd.proton.spam-threshold" "*", spamtest :value "ge" :comparator "i;ascii-numeric" "\${1}") {
    return;
}
# Invoices
if anyof (header :comparator "i;unicode-casemap" :contains "Subject" "invoice") {
    fileinto "archive";
    addflag "\\\\Seen";
}
# Somewhere else
if address :all :is "From" "boss@x.test" {
    fileinto "No such folder";
}`

test('a Sieve script imported into filters, and the filters exported as Sieve', async ({ browser }) => {
  test.slow()
  const alice = newAccount('sieve', PASSWORD)
  const context = await browser.newContext({ viewport: { width: 1400, height: 900 }, acceptDownloads: true })
  await registerAccount(context, alice)
  const mail = await context.newPage()
  await mail.goto(appUrl('mail', '/settings/filters'))
  await expect(mail.getByRole('heading', { name: 'Filters' })).toBeVisible({ timeout: 120_000 })

  await mail.getByRole('button', { name: 'Import Sieve' }).click()
  const dialog = mail.getByTestId('sieve-import')
  await dialog.getByRole('textbox', { name: 'Sieve script' }).fill(SCRIPT)
  await dialog.getByRole('button', { name: 'Read' }).click()
  await expect(dialog.getByText('1 filter to add')).toBeVisible()
  await expect(dialog.getByText('Invoices')).toBeVisible()
  await expect(dialog.getByText('1 part not imported')).toBeVisible()
  await expect(dialog.getByText('No such folder')).toBeVisible()
  await dialog.getByRole('button', { name: 'Add 1 filter' }).click()
  await expect(mail.getByText('1 filter added')).toBeVisible({ timeout: 30_000 })
  await expect(mail.getByText('Invoices', { exact: true })).toBeVisible()

  const download = mail.waitForEvent('download')
  await mail.getByRole('button', { name: 'Export as Sieve' }).click()
  const file = await download
  expect(file.suggestedFilename()).toBe('kutup-filters.sieve')
  const text = await readFile((await file.path())!, 'utf8')
  expect(text).toContain('# Invoices\nif anyof (header :comparator "i;unicode-casemap" :contains "Subject" "invoice")')
  expect(text).toContain('fileinto "archive";')
  expect(text).toContain('addflag "\\\\Seen";')

  await context.close()
})
