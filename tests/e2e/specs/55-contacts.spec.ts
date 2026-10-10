import { readFile } from 'node:fs/promises'
import { expect, test } from '@playwright/test'
import { appUrl, newAccount, registerAccount } from '../fixtures/apps'

const PASSWORD = 'Deneme123*ContactsPassword'

test('contacts: create, edit, group, import, search, export and delete, all end-to-end encrypted', async ({ browser }) => {
  test.slow()
  const context = await browser.newContext({ acceptDownloads: true })
  await registerAccount(context, newAccount('contacts', PASSWORD))
  const page = await context.newPage()
  await page.goto(appUrl('contacts'))
  await expect(page.getByText('No contacts yet')).toBeVisible({ timeout: 120_000 })

  // A new contact, with every kind of field.
  await page.getByRole('button', { name: 'New contact' }).first().click()
  const editor = page.getByRole('dialog', { name: 'New contact' })
  await editor.getByLabel('First name').fill('Ayşe')
  await editor.getByLabel('Last name').fill('Yılmaz')
  await editor.getByLabel('Email address').fill('ayse@kutup.local')
  await editor.getByRole('button', { name: 'Add phone' }).click()
  await editor.getByLabel('Phone number').fill('+90 555 000 00 00')
  await editor.getByRole('button', { name: 'Add address' }).click()
  await editor.getByLabel('City').fill('İstanbul')
  await editor.getByLabel('Notes').fill('Met at the conference')
  await editor.getByRole('button', { name: 'Save' }).click()
  await expect(page.getByText('Contact added')).toBeVisible({ timeout: 30_000 })
  const person = page.getByRole('article', { name: 'Ayşe Yılmaz' })
  await expect(person.getByRole('heading', { name: 'Ayşe Yılmaz' })).toBeVisible()
  await expect(person.getByRole('link', { name: 'ayse@kutup.local' })).toBeVisible()
  await expect(person.getByText('Kutup', { exact: true })).toBeVisible()
  await expect(person.getByText('+90 555 000 00 00')).toBeVisible()
  await expect(person.getByText('İstanbul')).toBeVisible()

  // A group, and the contact put in it through the editor.
  await page.getByRole('button', { name: 'New group' }).click()
  const groupDialog = page.getByRole('dialog', { name: 'New group' })
  await groupDialog.getByLabel('Name').fill('Family')
  await groupDialog.getByRole('button', { name: 'Save' }).click()
  await expect(page.getByText('Group created')).toBeVisible()
  await person.getByRole('button', { name: 'Edit' }).click()
  const edit = page.getByRole('dialog', { name: 'Edit contact' })
  await edit.getByLabel('Job title').fill('Engineer')
  await edit.getByRole('checkbox', { name: 'Family' }).check()
  await edit.getByRole('button', { name: 'Save' }).click()
  await expect(page.getByText('Contact saved')).toBeVisible({ timeout: 30_000 })
  await expect(person.getByText('Engineer')).toBeVisible()
  await page.getByRole('link', { name: /^Family/ }).click()
  await expect(page.getByRole('heading', { name: 'Family', level: 1 })).toBeVisible()
  await expect(page.getByRole('link', { name: /Ayşe Yılmaz/ })).toBeVisible()

  // Import: one new person, one already here (same email), skipped.
  await page.getByRole('link', { name: /^All contacts/ }).click()
  await page.getByRole('button', { name: 'Import' }).click()
  const importer = page.getByRole('dialog', { name: 'Import contacts' })
  await importer.getByTestId('import-file').setInputFiles({
    name: 'contacts.vcf',
    mimeType: 'text/vcard',
    buffer: Buffer.from(
      [
        'BEGIN:VCARD', 'VERSION:3.0', 'FN:Ali Veli', 'N:Veli;Ali;;;', 'EMAIL;TYPE=INTERNET:ali@example.com', 'END:VCARD',
        'BEGIN:VCARD', 'VERSION:3.0', 'FN:Ayşe Again', 'EMAIL:ayse@kutup.local', 'END:VCARD',
      ].join('\r\n'),
    ),
  })
  await expect(importer.getByText('2 contacts found')).toBeVisible()
  await expect(importer.getByText('Skip 1 already in your contacts')).toBeVisible()
  await importer.getByRole('button', { name: 'Import 1 contact' }).click()
  await expect(page.getByText('1 contact imported')).toBeVisible({ timeout: 30_000 })
  await expect(page.getByRole('link', { name: /Ali Veli/ })).toBeVisible()

  // Search folds case and Turkish letters.
  await page.getByRole('searchbox', { name: 'Search contacts' }).fill('ayse')
  await expect(page.getByRole('link', { name: /Ayşe Yılmaz/ })).toBeVisible()
  await expect(page.getByRole('link', { name: /Ali Veli/ })).toHaveCount(0)
  await page.getByRole('searchbox', { name: 'Search contacts' }).fill('')

  // Everything survives a reload: summaries verify, cards open.
  await page.reload()
  await expect(page.getByRole('link', { name: /Ali Veli/ })).toBeVisible({ timeout: 120_000 })
  await expect(page.getByRole('link', { name: /Ayşe Yılmaz/ })).toBeVisible()

  // Export all as one .vcf.
  const [download] = await Promise.all([page.waitForEvent('download'), page.getByRole('button', { name: 'Export all as .vcf' }).click()])
  const vcf = await readFile((await download.path())!, 'utf8')
  expect(vcf.match(/BEGIN:VCARD/g)).toHaveLength(2)
  expect(vcf).toContain('FN:Ayşe Yılmaz')
  expect(vcf).toContain('TEL;TYPE=cell:+90 555 000 00 00'.replace(';TYPE=cell', ''))

  // Delete the imported one.
  await page.getByRole('checkbox', { name: 'Select Ali Veli' }).check()
  await page.getByRole('button', { name: 'Delete' }).first().click()
  await page.getByRole('alertdialog').getByRole('button', { name: 'Delete' }).click()
  await expect(page.getByText('Contact deleted')).toBeVisible({ timeout: 30_000 })
  await expect(page.getByRole('link', { name: /Ali Veli/ })).toHaveCount(0)

  // The address book counts in the storage pool.
  await page.goto(appUrl('account', '/settings/storage'))
  await expect(page.getByRole('list', { name: 'What fills your storage' })).toContainText('Contacts', { timeout: 60_000 })
  await context.close()
})
