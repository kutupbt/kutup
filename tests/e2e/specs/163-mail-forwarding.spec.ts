import { expect, test, type BrowserContext, type Locator, type Page } from '@playwright/test'
import { apiUrl, appUrl, newAccount, registerAccount } from '../fixtures/apps'
import { openWhenArrived } from '../fixtures/mail'

// Mail forwarding (docs/plans/mail-forwarding.md), as Proton's:
// - end to end to a Kutup address here: set up in Settings → Forwarding,
//   accepted by the forwardee in theirs, then mail to the forwarder reaches
//   the forwardee too (the forwarder keeps the original) and opens with the
//   forwarding key, which the forwardee's key page shows as delete-only;
//   paused (nothing forwarded meanwhile), resumed and deleted from the
//   forwarder's side;
// - outside: the confirmation step says end-to-end encryption goes off for
//   the address, the address's signed key list says so while it lasts (a
//   sender's composer reads it from there), and deleting the forwarding
//   turns it back on;
// - the outside recipient's confirmation page needs no account, and drops
//   the token from the address bar.

const PASSWORD = 'Deneme123*MailForwardingPassword'

async function openMail(context: BrowserContext): Promise<Page> {
  const page = await context.newPage()
  await page.goto(appUrl('mail'))
  await expect(page.getByRole('heading', { name: 'Inbox' })).toBeVisible({ timeout: 120_000 })
  return page
}

async function openForwarding(page: Page) {
  await page.goto(appUrl('mail', '/settings/forwarding'))
  await expect(page.getByRole('heading', { name: 'Forwarding' })).toBeVisible({ timeout: 60_000 })
}

async function write(page: Page, to: string, subject: string, beforeSending?: (composer: Locator) => Promise<void>) {
  await page.getByRole('button', { name: 'New message' }).first().click()
  const composer = page.getByRole('dialog', { name: 'New message' })
  await composer.getByRole('combobox', { name: 'To' }).fill(to)
  await composer.getByRole('combobox', { name: 'To' }).press('Enter')
  await beforeSending?.(composer)
  await composer.getByRole('textbox', { name: 'Subject' }).fill(subject)
  await page.getByRole('textbox', { name: 'Message' }).fill(`${subject} gövdesi`)
  await page.getByRole('dialog', { name: subject }).getByRole('button', { name: 'Send', exact: true }).click()
  await expect(page.getByText('Message sent').first()).toBeVisible({ timeout: 60_000 })
  await expect(page.getByRole('button', { name: /^Send(ing…)?$/ })).toHaveCount(0, { timeout: 60_000 })
}

/** Starts a forwarding to `to` and stops at its confirmation step. */
async function startForwarding(page: Page, to: string) {
  await page.getByTestId('forwarding-add').click()
  const dialog = page.getByTestId('forwarding-dialog')
  await dialog.getByTestId('forwarding-to').fill(to)
  await dialog.getByTestId('forwarding-next').click()
  await expect(dialog.getByTestId('forwarding-confirm')).toBeVisible({ timeout: 60_000 })
  // The server, with the recipient, could read all of the address's mail: said every time.
  await expect(dialog.getByTestId('forwarding-trust-hint')).toBeVisible()
  return dialog
}

test('forwarding: end to end set up, accepted, received, paused and deleted; outside turns encryption off and back on', async ({ browser, request }) => {
  test.slow()
  const settings = (await (await request.get(apiUrl('/auth/settings'))).json()) as { chat: { serverName: string } }
  const domain = settings.chat.serverName
  const alice = newAccount('fwdalice', PASSWORD)
  const bob = newAccount('fwdbob', PASSWORD)
  const carol = newAccount('fwdcarol', PASSWORD)
  const aliceContext = await browser.newContext({ viewport: { width: 1400, height: 900 } })
  const bobContext = await browser.newContext()
  const carolContext = await browser.newContext()
  await registerAccount(aliceContext, alice)
  await registerAccount(bobContext, bob)
  await registerAccount(carolContext, carol)
  const mail = await openMail(aliceContext)
  const bobMail = await openMail(bobContext)
  const carolMail = await openMail(carolContext)
  const aliceAddress = `${alice.username}@${domain}`
  const bobAddress = `${bob.username}@${domain}`
  const tag = Date.now().toString(36)

  // Alice forwards everything to Bob: end to end, pending until he accepts.
  await openForwarding(mail)
  const dialog = await startForwarding(mail, bobAddress)
  await expect(dialog.getByText('End-to-end encrypted', { exact: true })).toBeVisible()
  await expect(dialog.getByTestId('forwarding-outside-warning')).toHaveCount(0)
  await dialog.getByTestId('forwarding-submit').click()
  const outgoing = mail.getByTestId('forwarding-list-outgoing')
  await expect(outgoing.getByTestId('forwarding-row')).toHaveAttribute('data-state', 'pending', { timeout: 60_000 })

  // Bob accepts in his settings ("To me").
  await openForwarding(bobMail)
  await bobMail.getByRole('tab', { name: 'To me' }).click()
  const incoming = bobMail.getByTestId('forwarding-list-incoming')
  await expect(incoming.getByText(aliceAddress)).toBeVisible({ timeout: 60_000 })
  await incoming.getByTestId('forwarding-accept').click()
  await expect(incoming.getByTestId('forwarding-row')).toHaveAttribute('data-state', 'active', { timeout: 60_000 })
  await mail.reload()
  await expect(mail.getByTestId('forwarding-list-outgoing').getByTestId('forwarding-row')).toHaveAttribute('data-state', 'active', {
    timeout: 60_000,
  })

  // Carol writes to Alice: Bob gets the copy, and it opens with his forwarding key.
  const forwarded = `Yönlendirilen ${tag}`
  await write(carolMail, aliceAddress, forwarded)
  await bobMail.goto(appUrl('mail', '/inbox'))
  await openWhenArrived(bobMail, new RegExp(forwarded))
  await expect(bobMail.frameLocator('iframe[title="Message"]').last().getByText(`${forwarded} gövdesi`)).toBeVisible({ timeout: 60_000 })
  // Alice keeps the original.
  await mail.goto(appUrl('mail', '/inbox'))
  await openWhenArrived(mail, new RegExp(forwarded))
  await expect(mail.frameLocator('iframe[title="Message"]').last().getByText(`${forwarded} gövdesi`)).toBeVisible({ timeout: 60_000 })
  // Bob's key page shows the forwarding key apart: it can only be deleted.
  const bobKeys = await bobContext.newPage()
  await bobKeys.goto(appUrl('account', '/settings/keys'))
  const forwardingKey = bobKeys.getByTestId('mail-forwarding-key')
  await expect(forwardingKey).toBeVisible({ timeout: 60_000 })
  await expect(forwardingKey.getByText('Forwarding', { exact: true })).toBeVisible()
  await expect(forwardingKey.getByRole('button', { name: 'Delete', exact: true })).toBeVisible()
  await expect(forwardingKey.getByRole('button', { name: /Download public key|More key actions/ })).toHaveCount(0)
  await bobKeys.close()

  // Paused, nothing goes; resumed; deleted.
  await openForwarding(mail)
  const row = mail.getByTestId('forwarding-list-outgoing').getByTestId('forwarding-row')
  await row.getByRole('button', { name: 'Pause' }).click()
  await expect(row).toHaveAttribute('data-state', 'paused', { timeout: 60_000 })
  // Mail while paused reaches Alice alone.
  const whilePaused = `Duraklatılmış ${tag}`
  await write(carolMail, aliceAddress, whilePaused)
  await openWhenArrived(mail, new RegExp(whilePaused))
  // A forward is sent right after the copy is stored: give it time to (not) come.
  await bobMail.waitForTimeout(5_000)
  await bobMail.goto(appUrl('mail', '/inbox'))
  await expect(bobMail.getByRole('link', { name: new RegExp(forwarded) }).first()).toBeVisible({ timeout: 60_000 })
  await expect(bobMail.getByRole('link', { name: new RegExp(whilePaused) })).toHaveCount(0)
  await openForwarding(mail)
  await row.getByRole('button', { name: 'Resume' }).click()
  await expect(row).toHaveAttribute('data-state', 'active', { timeout: 60_000 })
  await row.getByRole('button', { name: 'Delete' }).click()
  await mail.getByRole('alertdialog').getByRole('button', { name: 'Delete' }).click()
  await expect(mail.getByText('No forwarding yet')).toBeVisible({ timeout: 60_000 })

  // Outside Kutup: the confirmation says encryption goes off for the address,
  // the page says so while it lasts, and deleting it turns encryption back on.
  const outside = `fwd-${tag}@example.com`
  const outsideDialog = await startForwarding(mail, outside)
  await expect(outsideDialog.getByText('Not end-to-end encrypted', { exact: true })).toBeVisible()
  await expect(outsideDialog.getByTestId('forwarding-outside-warning')).toContainText(aliceAddress)
  await outsideDialog.getByTestId('forwarding-submit').click()
  await expect(mail.getByTestId('forwarding-encryption-off')).toBeVisible({ timeout: 60_000 })
  await expect(mail.getByTestId('forwarding-list-outgoing').getByText(outside)).toBeVisible()
  const keys = await aliceContext.newPage()
  await keys.goto(appUrl('account', '/settings/keys'))
  await expect(keys.getByTestId('mail-keys-encryption-off')).toBeVisible({ timeout: 60_000 })
  // Carol's composer reads it from Alice's signed key list: an open lock, and
  // the mail still reaches Alice (sealed when it arrives).
  await carolMail.reload()
  const readable = `Okunur ${tag}`
  await write(carolMail, aliceAddress, readable, async (composer) => {
    await expect(composer.getByTestId('recipient-encryption-disabled')).toBeVisible({ timeout: 60_000 })
  })
  await openWhenArrived(mail, new RegExp(readable))
  await openForwarding(mail)
  const outsideRow = mail.getByTestId('forwarding-list-outgoing').getByTestId('forwarding-row')
  await outsideRow.getByRole('button', { name: 'Delete' }).click()
  await mail.getByRole('alertdialog').getByRole('button', { name: 'Delete' }).click()
  await expect(mail.getByText('No forwarding yet')).toBeVisible({ timeout: 60_000 })
  // The deletion owes a key list without the flag; Mail signs it on its next look.
  await expect(async () => {
    await mail.reload()
    await expect(mail.getByTestId('forwarding-encryption-off')).toHaveCount(0, { timeout: 5_000 })
  }).toPass({ timeout: 60_000 })
  await keys.reload()
  await expect(keys.getByTestId('mail-keys-encryption-off')).toHaveCount(0, { timeout: 60_000 })
  // The signed list has encryption on again: Carol's composer locks.
  await carolMail.reload()
  await expect(carolMail.getByRole('heading', { name: 'Inbox' })).toBeVisible({ timeout: 120_000 })
  await carolMail.getByRole('button', { name: 'New message' }).first().click()
  const composer = carolMail.getByRole('dialog', { name: 'New message' })
  await composer.getByRole('combobox', { name: 'To' }).fill(aliceAddress)
  await composer.getByRole('combobox', { name: 'To' }).press('Enter')
  await expect(composer.getByRole('img', { name: 'End-to-end encrypted: a Kutup address' })).toBeVisible({ timeout: 60_000 })
  await expect(composer.getByTestId('recipient-encryption-disabled')).toHaveCount(0)

  // The outside recipient's page: no account needed; a link that isn't
  // valid says so, and the token leaves the address bar.
  const visitor = await browser.newContext()
  const page = await visitor.newPage()
  await page.goto(appUrl('account', `/email-forwarding#made-up-${tag}`))
  await expect(page.getByTestId('email-forwarding-problem')).toContainText("This link isn't valid", { timeout: 60_000 })
  expect(new URL(page.url()).hash).toBe('')
  await visitor.close()

  await aliceContext.close()
  await bobContext.close()
  await carolContext.close()
})
