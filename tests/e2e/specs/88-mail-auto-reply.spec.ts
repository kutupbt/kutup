import { expect, test, type BrowserContext, type Page } from '@playwright/test'
import { apiUrl, appUrl, newAccount, registerAccount } from '../fixtures/apps'

// Auto-reply (docs/plans/mail-parity.md, P2), as Proton's: turned on in Mail →
// Settings, it answers a message once; the answer carries Proton's banner
// for automatic replies and stays in the sender's Sent.

const PASSWORD = 'Deneme123*MailAutoReplyPassword'
const SHOTS = process.env.MAIL_UX_SHOTS

async function openMail(context: BrowserContext): Promise<Page> {
  const page = await context.newPage()
  await page.goto(appUrl('mail'))
  await expect(page.getByRole('heading', { name: 'Inbox' })).toBeVisible({ timeout: 120_000 })
  return page
}

test('auto-reply: turned on in Settings, answers once, marked automatic', async ({ browser, request }) => {
  test.slow()
  const settings = (await (await request.get(apiUrl('/auth/settings'))).json()) as { chat: { serverName: string } }
  const domain = settings.chat.serverName
  const alice = newAccount('aralice', PASSWORD)
  const bob = newAccount('arbob', PASSWORD)
  const aliceContext = await browser.newContext({ viewport: { width: 1400, height: 900 } })
  const bobContext = await browser.newContext({ viewport: { width: 1400, height: 900 } })
  await registerAccount(aliceContext, alice)
  await registerAccount(bobContext, bob)
  const mail = await openMail(aliceContext)
  const bobMail = await openMail(bobContext)
  const tag = Date.now().toString(36)

  // Alice: on until she turns it off, with her own words.
  await mail.goto(appUrl('mail', '/settings/auto-reply'))
  await expect(mail.getByRole('heading', { name: 'Auto-reply' })).toBeVisible()
  await mail.getByRole('checkbox', { name: /Auto-reply/ }).click()
  // Proton's default: a fixed week from now.
  await expect(mail.getByText('Auto-reply is active from the start time to the end time.')).toBeVisible()
  await mail.getByRole('combobox', { name: 'Duration' }).click()
  await mail.getByRole('option', { name: 'Permanent' }).click()
  await expect(mail.getByText('Auto-reply is active until you turn it off.')).toBeVisible()
  const editor = mail.getByLabel('Message', { exact: true })
  await editor.click()
  await mail.keyboard.press('Control+A')
  await mail.keyboard.type(`Tatildeyim ${tag}`)
  await mail.getByRole('button', { name: 'Save' }).click()
  await expect(mail.getByText('Auto-reply updated')).toBeVisible({ timeout: 30_000 })
  await expect(mail.getByText(/On: mail that reaches your inbox now gets this answer/)).toBeVisible()
  if (SHOTS) await mail.screenshot({ path: `${SHOTS}/auto-reply-settings.png` })

  // Bob writes to Alice twice; one answer comes back.
  const send = async (subject: string) => {
    await bobMail.getByRole('button', { name: 'New message' }).first().click()
    const composer = bobMail.getByRole('dialog', { name: 'New message' })
    await composer.getByRole('combobox', { name: 'To' }).fill(`${alice.username}@${domain}`)
    await composer.getByRole('combobox', { name: 'To' }).press('Enter')
    await composer.getByRole('textbox', { name: 'Subject' }).fill(subject)
    await bobMail.getByRole('textbox', { name: 'Message' }).fill(`${subject} gövdesi`)
    await bobMail.getByRole('dialog', { name: subject }).getByRole('button', { name: 'Send', exact: true }).click()
    await expect(bobMail.getByText('Message sent').first()).toBeVisible({ timeout: 60_000 })
    // The toast may be the last send's: wait for this composer to close.
    await expect(bobMail.getByRole('button', { name: /^Send(ing…)?$/ })).toHaveCount(0, { timeout: 60_000 })
  }
  const first = `Soru ${tag}`
  await send(first)
  await send(`İkinci ${tag}`)
  const answers = bobMail.getByRole('link', { name: /Auto: / })
  await expect(async () => {
    await bobMail.reload()
    await expect(answers).toHaveCount(1, { timeout: 2_000 })
  }).toPass({ timeout: 60_000 })
  await bobMail.getByRole('link', { name: new RegExp(`Auto: ${first}`) }).click()
  await expect(bobMail.getByText('This message was written automatically in answer to an earlier message.')).toBeVisible({ timeout: 60_000 })
  await expect(bobMail.frameLocator('iframe[title="Message"]').last().getByText(`Tatildeyim ${tag}`)).toBeVisible({ timeout: 60_000 })
  if (SHOTS) await bobMail.screenshot({ path: `${SHOTS}/auto-reply-received.png` })
  await expect(answers).toHaveCount(1)

  // Alice finds the answer in Sent.
  await mail.goto(appUrl('mail', '/sent'))
  await expect(mail.getByRole('link', { name: new RegExp(`Auto: ${first}`) })).toBeVisible({ timeout: 60_000 })

  // Turning it off takes effect at once.
  await mail.goto(appUrl('mail', '/settings/auto-reply'))
  await mail.getByRole('checkbox', { name: /Auto-reply/ }).click()
  await expect(mail.getByText('Auto-reply disabled')).toBeVisible({ timeout: 30_000 })

  await aliceContext.close()
  await bobContext.close()
})
