import { expect, test, type BrowserContext, type Page } from '@playwright/test'
import { apiUrl, appUrl, newAccount, registerAccount } from '../fixtures/apps'

// People in Mail: a sender who is not in Contacts gets a banner on their
// message with Save to contacts, as a new contact or another address of
// someone already there; names open a card on hover; in a dark theme the
// body follows it, and the quoted earlier message is folded.

const PASSWORD = 'Deneme123*MailPeoplePassword'
const SHOTS = process.env.MAIL_UX_SHOTS

async function openMail(context: BrowserContext): Promise<Page> {
  const page = await context.newPage()
  await page.goto(appUrl('mail'))
  await expect(page.getByRole('heading', { name: 'Inbox' })).toBeVisible({ timeout: 120_000 })
  return page
}

async function write(page: Page, to: string, subject: string, body: string) {
  await page.getByRole('button', { name: 'New message' }).first().click()
  const composer = page.getByRole('dialog', { name: 'New message' })
  await composer.getByRole('combobox', { name: 'To' }).fill(to)
  await composer.getByRole('combobox', { name: 'To' }).press('Enter')
  await composer.getByRole('textbox', { name: 'Subject' }).fill(subject)
  await page.getByRole('textbox', { name: 'Message' }).fill(body)
  await page.getByRole('dialog', { name: subject }).getByRole('button', { name: 'Send', exact: true }).click()
  await expect(page.getByText('Message sent')).toBeVisible({ timeout: 60_000 })
}

async function shot(page: Page, name: string) {
  if (SHOTS) await page.screenshot({ path: `${SHOTS}/${name}.png` })
}

test('saving senders to contacts, person cards, a dark body and folded quotes', async ({ browser, request }) => {
  test.slow()
  const settings = (await (await request.get(apiUrl('/auth/settings'))).json()) as { chat: { serverName: string } }
  const domain = settings.chat.serverName
  const alice = newAccount('pplalice', PASSWORD)
  const bob = newAccount('pplbob', PASSWORD)
  const carol = newAccount('pplcarol', PASSWORD)
  const aliceContext = await browser.newContext({ colorScheme: 'dark', viewport: { width: 1400, height: 900 } })
  const bobContext = await browser.newContext({ viewport: { width: 1400, height: 900 } })
  const carolContext = await browser.newContext()
  await registerAccount(aliceContext, alice)
  await registerAccount(bobContext, bob)
  await registerAccount(carolContext, carol)
  const aliceMail = await openMail(aliceContext)
  const bobMail = await openMail(bobContext)
  const carolMail = await openMail(carolContext)
  const tag = Date.now().toString(36)
  const bobAddress = `${bob.username}@${domain}`
  const carolAddress = `${carol.username}@${domain}`

  // Bob writes to Alice, who has nobody in her contacts.
  const subject = `Tanışma ${tag}`
  await write(bobMail, `${alice.username}@${domain}`, subject, 'Merhaba Alice, ben Bob.')
  await aliceMail.reload()
  await aliceMail.getByRole('link', { name: new RegExp(subject) }).click()
  const body = aliceMail.frameLocator('iframe[title="Message"]').last()
  await expect(body.getByText('Merhaba Alice, ben Bob.')).toBeVisible({ timeout: 60_000 })

  // Dark theme: Kutup's own mail paints nothing, so it takes the theme's colours.
  const background = await body.locator('body').evaluate((el) => getComputedStyle(el).backgroundColor)
  expect(background).not.toBe('rgb(255, 255, 255)')

  // Kutup names a sender by their username until they set a display name.
  const banner = aliceMail.getByText(`${bob.username} is not in your contacts.`)
  await expect(banner).toBeVisible({ timeout: 60_000 })
  await shot(aliceMail, 'banner-dark')

  // Hovering his name opens his card, with Save to contacts.
  await aliceMail.getByRole('article').getByRole('button', { name: new RegExp(`More about .*${bob.username}`) }).first().hover()
  const card = aliceMail.getByRole('dialog').filter({ hasText: 'New message' })
  await expect(card.getByRole('button', { name: 'Save to contacts' })).toBeVisible({ timeout: 5_000 })
  await shot(aliceMail, 'card-dark')

  // Saved as a new contact, with a name; the banner goes and the name shows.
  await card.getByRole('button', { name: 'Save to contacts' }).click()
  const dialog = aliceMail.getByRole('dialog', { name: 'Save to contacts' })
  await expect(dialog.getByRole('radio', { name: /New contact/ })).toHaveAttribute('aria-checked', 'true')
  // "Add to a contact" needs someone there first.
  await expect(dialog.getByRole('radio', { name: /Add to a contact/ })).toBeDisabled()
  await dialog.getByLabel('Name').fill('Bob Builder')
  await shot(aliceMail, 'save-new-dark')
  await dialog.getByRole('button', { name: 'Save', exact: true }).click()
  await expect(aliceMail.getByText(`${bobAddress} saved to your contacts.`)).toBeVisible({ timeout: 60_000 })
  await expect(banner).toHaveCount(0)
  await expect(aliceMail.getByRole('article').getByRole('button', { name: /More about Bob Builder/ })).toBeVisible()
  await expect(aliceMail.getByRole('listitem').filter({ hasText: subject }).getByText('Bob Builder')).toBeVisible()

  // Carol writes too; Alice adds her address to Bob's contact instead.
  const second = `İkinci adres ${tag}`
  await write(carolMail, `${alice.username}@${domain}`, second, 'Bu da Bob’un iş adresi.')
  await aliceMail.goto(appUrl('mail', '/inbox'))
  await aliceMail.getByRole('link', { name: new RegExp(second) }).click()
  await aliceMail.getByRole('button', { name: 'Save to contacts' }).click()
  const existing = aliceMail.getByRole('dialog', { name: 'Save to contacts' })
  await existing.getByRole('radio', { name: /Add to a contact/ }).click()
  await existing.getByRole('searchbox', { name: 'Search contacts' }).fill('Builder')
  await existing.getByRole('option', { name: /Bob Builder/ }).click()
  await shot(aliceMail, 'save-existing-dark')
  await existing.getByRole('button', { name: 'Save', exact: true }).click()
  await expect(aliceMail.getByText(`${carolAddress} saved to your contacts.`)).toBeVisible({ timeout: 60_000 })
  await expect(aliceMail.getByRole('article').getByRole('button', { name: /More about Bob Builder/ })).toBeVisible()

  // Alice replies to Bob; on his side the quote of his own message is folded.
  await aliceMail.goto(appUrl('mail', '/inbox'))
  await aliceMail.getByRole('link', { name: new RegExp(subject) }).click()
  await aliceMail.getByRole('button', { name: 'Reply', exact: true }).click()
  const reply = aliceMail.getByRole('dialog', { name: `Re: ${subject}` })
  await aliceMail.getByRole('textbox', { name: 'Message' }).press('Control+Home')
  await aliceMail.keyboard.type('Memnun oldum Bob.')
  await reply.getByRole('button', { name: 'Send', exact: true }).click()
  await expect(aliceMail.getByText('Message sent')).toBeVisible({ timeout: 60_000 })
  await bobMail.reload()
  await bobMail.getByRole('link', { name: new RegExp(`Re: ${subject}`) }).click()
  const answer = bobMail.frameLocator('iframe[title="Message"]').last()
  await expect(answer.getByText('Memnun oldum Bob.')).toBeVisible({ timeout: 60_000 })
  await expect(answer.getByText('Merhaba Alice, ben Bob.')).toBeHidden()
  await shot(bobMail, 'quote-folded-light')
  await answer.getByRole('button', { name: 'Show quoted text' }).or(answer.locator('summary')).first().click()
  await expect(answer.getByText('Merhaba Alice, ben Bob.')).toBeVisible()
  await shot(bobMail, 'quote-open-light')

  await aliceContext.close()
  await bobContext.close()
  await carolContext.close()
})
