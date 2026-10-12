import { expect, test } from '@playwright/test'
import { apiUrl, appUrl, newAccount, registerAccount } from '../fixtures/apps'
import { openWhenArrived } from '../fixtures/mail'

// Expiring messages (docs/plans/mail-parity.md, P5), as Proton's: set in
// the composer's More options, said on the received message; outside
// recipients are refused, as their copy cannot be deleted. (Deleting every
// copy when the time comes is the mail gate's.)

const PASSWORD = 'Deneme123*MailExpiringPassword'

test('an expiring message: set, sent, said; not to outside addresses', async ({ browser, request }) => {
  test.slow()
  const settings = (await (await request.get(apiUrl('/auth/settings'))).json()) as { chat: { serverName: string } }
  const domain = settings.chat.serverName
  const context = await browser.newContext({ viewport: { width: 1400, height: 900 } })
  const alice = newAccount('exalice', PASSWORD)
  await registerAccount(context, alice)
  const mail = await context.newPage()
  await mail.goto(appUrl('mail'))
  await expect(mail.getByRole('heading', { name: 'Inbox' })).toBeVisible({ timeout: 120_000 })
  const write = async (to: string, subject: string) => {
    await mail.getByRole('button', { name: 'New message' }).first().click()
    const composer = mail.getByRole('dialog', { name: 'New message' })
    await composer.getByRole('combobox', { name: 'To' }).fill(to)
    await composer.getByRole('combobox', { name: 'To' }).press('Enter')
    await composer.getByRole('textbox', { name: 'Subject' }).fill(subject)
    await mail.getByRole('textbox', { name: 'Message' }).fill('Bu ileti silinecek.')
    const named = mail.getByRole('dialog', { name: subject })
    await named.getByRole('button', { name: 'More options' }).click()
    await mail.getByRole('menuitem', { name: 'Set expiration' }).click()
    await mail.getByRole('dialog', { name: 'Expiring message' }).getByRole('button', { name: 'Set' }).click()
    await expect(named.getByText(/This message expires on/)).toBeVisible()
    return named
  }

  // To a Kutup address: sent, and the received copy says when it goes.
  const subject = `Süreli ${Date.now().toString(36)}`
  const named = await write(`${alice.username}@${domain}`, subject)
  await named.getByRole('button', { name: 'Send', exact: true }).click()
  await expect(mail.getByRole('button', { name: /^Send(ing…)?$/ })).toHaveCount(0, { timeout: 60_000 })
  await openWhenArrived(mail, new RegExp(subject))
  await expect(mail.getByText(/This message will expire on/).first()).toBeVisible({ timeout: 60_000 })
  await expect(mail.getByRole('listitem').filter({ hasText: subject }).getByRole('img', { name: /^Expires / }).first()).toBeVisible()

  // To an outside address: refused, the composer stays.
  const outside = await write('someone@example.org', `Dışarı ${Date.now().toString(36)}`)
  await outside.getByRole('button', { name: 'Send', exact: true }).click()
  await expect(mail.getByText(/Expiring messages go to Kutup recipients only/)).toBeVisible({ timeout: 60_000 })
  await expect(outside).toBeVisible()
  await context.close()
})
