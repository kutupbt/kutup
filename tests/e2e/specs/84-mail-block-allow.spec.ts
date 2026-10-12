import { expect, test, type BrowserContext, type Page } from '@playwright/test'
import { apiUrl, appUrl, newAccount, registerAccount } from '../fixtures/apps'

// Block, spam and allow lists (docs/plans/mail-filters.md, F3): "Block
// messages from this sender" on the person card, Proton's wording; blocked
// mail never arrives; Settings moves the sender to Spam, then removes it.

const PASSWORD = 'Deneme123*MailBlockPassword'
const SHOTS = process.env.MAIL_UX_SHOTS

async function openMail(context: BrowserContext): Promise<Page> {
  const page = await context.newPage()
  await page.goto(appUrl('mail'))
  await expect(page.getByRole('heading', { name: 'Inbox' })).toBeVisible({ timeout: 120_000 })
  return page
}

async function write(page: Page, to: string, subject: string) {
  await page.getByRole('button', { name: 'New message' }).first().click()
  const composer = page.getByRole('dialog', { name: 'New message' })
  await composer.getByRole('combobox', { name: 'To' }).fill(to)
  await composer.getByRole('combobox', { name: 'To' }).press('Enter')
  await composer.getByRole('textbox', { name: 'Subject' }).fill(subject)
  await page.getByRole('textbox', { name: 'Message' }).fill(`${subject} gövdesi`)
  await page.getByRole('dialog', { name: subject }).getByRole('button', { name: 'Send', exact: true }).click()
  await expect(page.getByText('Message sent').first()).toBeVisible({ timeout: 60_000 })
  // The toast may be the last send's: wait for this composer to close.
  await expect(page.getByRole('button', { name: 'Send', exact: true })).toHaveCount(0, { timeout: 60_000 })
}

test('block a sender from the card, move them to Spam in Settings, remove them', async ({ browser, request }) => {
  test.slow()
  const settings = (await (await request.get(apiUrl('/auth/settings'))).json()) as { chat: { serverName: string } }
  const domain = settings.chat.serverName
  const alice = newAccount('blkalice', PASSWORD)
  const bob = newAccount('blkbob', PASSWORD)
  const aliceContext = await browser.newContext({ viewport: { width: 1400, height: 900 } })
  const bobContext = await browser.newContext()
  await registerAccount(aliceContext, alice)
  await registerAccount(bobContext, bob)
  const mail = await openMail(aliceContext)
  const bobMail = await openMail(bobContext)
  const to = `${alice.username}@${domain}`
  const bobAddress = `${bob.username}@${domain}`
  const tag = Date.now().toString(36)
  const list = mail.getByRole('list', { name: 'Messages' })
  const row = (subject: string) => list.getByRole('listitem').filter({ hasText: subject })
  const nav = mail.getByRole('navigation')

  // Bob's first message; Alice blocks him from his card.
  await write(bobMail, to, `Merhaba ${tag}`)
  await mail.reload()
  await row(`Merhaba ${tag}`).getByRole('link').click()
  await mail.getByRole('article').getByRole('button', { name: new RegExp(`More about .*${bob.username}`) }).first().click()
  await mail.getByRole('button', { name: 'Block messages from this sender' }).click()
  const dialog = mail.getByRole('dialog', { name: 'Block sender' })
  await expect(dialog.getByText(`New emails from ${bobAddress} won’t be delivered and will be permanently deleted.`)).toBeVisible()
  if (SHOTS) await mail.screenshot({ path: `${SHOTS}/block-sender.png` })
  await dialog.getByRole('button', { name: 'Block', exact: true }).click()
  await expect(mail.getByText(`${bobAddress} blocked.`)).toBeVisible({ timeout: 30_000 })

  // His next message is not delivered anywhere (his side says it was sent).
  await write(bobMail, to, `Engellenen ${tag}`)
  const sentinel = `Sonra ${tag}`
  // Settings: he is listed as blocked; move him to Spam.
  await mail.goto(appUrl('mail', '/settings/senders'))
  await expect(mail.getByRole('heading', { name: 'Block and allow' })).toBeVisible()
  const entry = mail.getByRole('listitem').filter({ hasText: bobAddress })
  await expect(entry).toBeVisible()
  if (SHOTS) await mail.screenshot({ path: `${SHOTS}/senders-settings.png` })
  await entry.getByRole('combobox', { name: `List for ${bobAddress}` }).click()
  await mail.getByRole('option', { name: 'Spam' }).click()
  await expect(mail.getByRole('tab', { name: 'Spam (1)' })).toBeVisible({ timeout: 30_000 })
  await write(bobMail, to, sentinel)
  await nav.getByRole('link', { name: /^Spam/ }).click()
  await expect(row(sentinel)).toBeVisible({ timeout: 60_000 })
  // The blocked one never arrived, in Spam, the Inbox or the Trash.
  await expect(row(`Engellenen ${tag}`)).toHaveCount(0)
  for (const folder of [/^Inbox/, /^Trash/]) {
    await nav.getByRole('link', { name: folder }).click()
    await expect(row(`Engellenen ${tag}`)).toHaveCount(0)
  }

  // Removed from the lists: mail arrives in the Inbox again.
  await mail.goto(appUrl('mail', '/settings/senders'))
  await mail.getByRole('button', { name: `Remove ${bobAddress}` }).click()
  await expect(mail.getByText(`${bobAddress} removed.`)).toBeVisible({ timeout: 30_000 })
  await write(bobMail, to, `Tekrar ${tag}`)
  await nav.getByRole('link', { name: /^Inbox/ }).click()
  await expect(row(`Tekrar ${tag}`)).toBeVisible({ timeout: 60_000 })

  await aliceContext.close()
  await bobContext.close()
})
