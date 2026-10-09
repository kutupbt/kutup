import { expect, test } from '@playwright/test'
import { openChat } from '../fixtures/chat'
import { createFolder, itemAction } from '../fixtures/drive'
import { appUrl, newAccount, openDrive, registerAccount } from '../fixtures/apps'

const PASSWORD = 'Deneme123*ContactPickersPassword'

test('Drive and Chat pickers suggest contacts, and "Add to contacts" opens a filled-in contact', async ({ browser }) => {
  test.slow()
  const context = await browser.newContext()
  await registerAccount(context, newAccount('pickers', PASSWORD))

  // One contact to be suggested.
  const contacts = await context.newPage()
  await contacts.goto(appUrl('contacts'))
  await expect(contacts.getByText('No contacts yet')).toBeVisible({ timeout: 120_000 })
  await contacts.getByRole('button', { name: 'New contact' }).first().click()
  const editor = contacts.getByRole('dialog', { name: 'New contact' })
  await editor.getByLabel('First name').fill('Ayşe')
  await editor.getByLabel('Last name').fill('Yılmaz')
  await editor.getByLabel('Email address').fill('ayse@kutup.local')
  await editor.getByRole('button', { name: 'Save' }).click()
  await expect(contacts.getByText('Contact added')).toBeVisible({ timeout: 30_000 })

  // Drive's share dialog suggests her after two letters; picking fills the address.
  const drive = await openDrive(context)
  await createFolder(drive, 'Trip')
  await itemAction(drive, 'Trip', 'Share')
  const share = drive.getByRole('dialog')
  const recipient = share.getByRole('combobox', { name: 'Email or Kutup address' })
  await recipient.fill('ay')
  const suggestion = share.getByRole('option', { name: /Ayşe Yılmaz/ })
  await expect(suggestion).toBeVisible({ timeout: 30_000 })
  await recipient.press('ArrowDown')
  await recipient.press('Enter')
  await expect(recipient).toHaveValue('ayse@kutup.local')
  await expect(share.getByRole('listbox')).toHaveCount(0)
  await drive.keyboard.press('Escape')

  // Chat's new-chat field suggests her by her name too.
  const chat = await openChat(context)
  await chat.getByRole('button', { name: 'New chat' }).first().click()
  const field = chat.getByRole('dialog').getByRole('combobox')
  await field.fill('yıl')
  await chat.getByRole('option', { name: /Ayşe Yılmaz/ }).click()
  await expect(field).toHaveValue('ayse@kutup.local')
  await chat.keyboard.press('Escape')

  // "Add to contacts" from another app opens the editor with the address in it.
  await contacts.goto(appUrl('contacts', '/?add=bob%40example.com'))
  const adding = contacts.getByRole('dialog', { name: 'New contact' })
  await expect(adding.getByLabel('Email address')).toHaveValue('bob@example.com', { timeout: 60_000 })
  await expect(contacts).not.toHaveURL(/add=/)
  await context.close()
})
