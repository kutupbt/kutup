import { expect, test, type BrowserContext, type Page } from '@playwright/test'
import { apiUrl, appUrl, newAccount, registerAccount } from '../fixtures/apps'

// Mail between two Kutup users (docs/plans/mail.md, C2): written in the
// browser, encrypted once for the recipient and the sender's copy, opened
// and verified on the other side; reply, star, archive, drafts.

const PASSWORD = 'Deneme123*MailPassword'

/** Opens Mail, which makes the address key itself if sign-in has not yet. */
async function openMail(context: BrowserContext): Promise<Page> {
  const page = await context.newPage()
  await page.goto(appUrl('mail'))
  await expect(page.getByRole('heading', { name: 'Inbox' })).toBeVisible({ timeout: 120_000 })
  return page
}

test('two Kutup users exchange end-to-end encrypted mail, with replies, filing and drafts', async ({ browser, request }) => {
  test.slow()
  const settings = (await (await request.get(apiUrl('/auth/settings'))).json()) as { chat: { serverName: string } }
  const domain = settings.chat.serverName
  const alice = newAccount('mailalice', PASSWORD)
  const bob = newAccount('mailbob', PASSWORD)
  const aliceContext = await browser.newContext()
  const bobContext = await browser.newContext()
  await registerAccount(aliceContext, alice)
  await registerAccount(bobContext, bob)
  const aliceMail = await openMail(aliceContext)
  const bobMail = await openMail(bobContext)
  const subject = `Toplantı ${Date.now().toString(36)}`

  // Alice writes to Bob, with an attachment.
  await aliceMail.getByRole('button', { name: 'New message' }).click()
  const composer = aliceMail.getByRole('dialog', { name: 'New message' })
  await composer.getByRole('combobox').first().fill(`${bob.username}@${domain}`)
  await composer.getByRole('combobox').first().press('Enter')
  await expect(composer.getByLabel('End-to-end encrypted: a Kutup address')).toBeVisible()
  await composer.getByRole('textbox', { name: 'Subject' }).fill(subject)
  await aliceMail.getByRole('textbox', { name: 'Message' }).fill('Çarşamba saat üçte görüşelim.')
  await aliceMail.locator('input[type="file"]').setInputFiles({ name: 'gündem.txt', mimeType: 'text/plain', buffer: Buffer.from('1. Bütçe\n') })
  const sending = aliceMail.getByRole('dialog', { name: subject })
  await expect(sending.getByText('gündem.txt')).toBeVisible()
  await expect(sending.getByLabel('Uploading')).toHaveCount(0, { timeout: 60_000 })
  await sending.getByRole('button', { name: 'Send', exact: true }).click()
  await expect(aliceMail.getByText('Message sent')).toBeVisible({ timeout: 60_000 })

  // Alice's copy is in Sent.
  await aliceMail.getByRole('link', { name: /^Sent( \d+)?$/ }).click()
  await expect(aliceMail.getByRole('link', { name: new RegExp(subject) })).toBeVisible({ timeout: 30_000 })

  // Bob finds it in his inbox, unread, opens it: decrypted, signed by Alice.
  await bobMail.reload()
  const row = bobMail.getByRole('link', { name: new RegExp(subject) })
  await expect(row).toBeVisible({ timeout: 60_000 })
  await row.click()
  await expect(bobMail.getByRole('img', { name: 'End-to-end encrypted, from a verified sender' }).first()).toBeVisible({ timeout: 60_000 })
  await expect(bobMail.frameLocator('iframe[title="Message"]').getByText('Çarşamba saat üçte görüşelim.')).toBeVisible()
  await expect(bobMail.getByRole('button', { name: /gündem\.txt/ })).toBeVisible()

  // Bob replies; the reply joins the thread on Alice's side.
  await bobMail.getByRole('button', { name: 'Reply', exact: true }).click()
  const reply = bobMail.getByRole('dialog', { name: `Re: ${subject}` })
  await expect(reply.getByTitle(`${alice.username}@${domain}`)).toBeVisible()
  await bobMail.getByRole('textbox', { name: 'Message' }).press('Control+Home')
  await bobMail.keyboard.type('Uygun, görüşürüz.')
  await reply.getByRole('button', { name: 'Send', exact: true }).click()
  await expect(bobMail.getByText('Message sent')).toBeVisible({ timeout: 60_000 })
  await aliceMail.getByRole('link', { name: /^Inbox( \d+)?$/ }).click()
  await aliceMail.reload()
  await aliceMail.getByRole('link', { name: new RegExp(`Re: ${subject}`) }).click()
  // The thread: her own message folded to a line, Bob's reply open.
  await expect(aliceMail.getByRole('article')).toHaveCount(1, { timeout: 30_000 })
  await expect(aliceMail.getByRole('button', { name: new RegExp(`${alice.username}.*End-to-end encrypted`) })).toBeVisible()
  await expect(aliceMail.frameLocator('iframe[title="Message"]').last().getByText('Uygun, görüşürüz.')).toBeVisible({ timeout: 60_000 })

  // Bob stars and archives the thread.
  await bobMail.getByRole('button', { name: 'Star', exact: true }).first().click()
  await bobMail.getByRole('link', { name: /^Starred( \d+)?$/ }).click()
  await expect(bobMail.getByRole('link', { name: new RegExp(subject) }).first()).toBeVisible({ timeout: 30_000 })
  await bobMail.getByRole('link', { name: new RegExp(subject) }).first().click()
  await bobMail.getByRole('button', { name: 'Archive', exact: true }).click()
  await expect(bobMail.getByText('Archived')).toBeVisible()
  await bobMail.getByRole('link', { name: /^Archive( \d+)?$/ }).click()
  await expect(bobMail.getByRole('link', { name: new RegExp(subject) }).first()).toBeVisible({ timeout: 30_000 })

  // A message closed before sending is kept in Drafts and opens again.
  await aliceMail.getByRole('button', { name: 'New message' }).click()
  const draft = aliceMail.getByRole('dialog', { name: 'New message' })
  await draft.getByRole('textbox', { name: 'Subject' }).fill(`Taslak ${subject}`)
  await aliceMail.getByRole('textbox', { name: 'Message' }).fill('Henüz bitmedi.')
  await expect(aliceMail.getByRole('dialog', { name: `Taslak ${subject}` }).getByText('Saved')).toBeVisible({ timeout: 30_000 })
  await aliceMail.getByRole('dialog', { name: `Taslak ${subject}` }).getByRole('button', { name: 'Close and keep the draft' }).click()
  await aliceMail.getByRole('link', { name: /^Drafts( \d+)?$/ }).click()
  await aliceMail.getByRole('link', { name: new RegExp(`Taslak ${subject}`) }).click()
  await aliceMail.getByRole('button', { name: 'Edit draft' }).click()
  await expect(aliceMail.getByRole('textbox', { name: 'Message' })).toContainText('Henüz bitmedi.')
  await aliceMail.getByRole('button', { name: 'Discard draft' }).click()
  await expect(aliceMail.getByRole('link', { name: new RegExp(`Taslak ${subject}`) })).toHaveCount(0, { timeout: 30_000 })

  await aliceContext.close()
  await bobContext.close()
})
