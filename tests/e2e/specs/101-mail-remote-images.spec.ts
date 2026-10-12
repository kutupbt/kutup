import { expect, test } from '@playwright/test'
import { apiUrl, appUrl, newAccount, registerAccount } from '../fixtures/apps'

// Remote images (docs/plans/mail-parity.md, P5): Proton's "Auto show remote
// images" for every sender, and senders whose images always load (chosen in
// the reader's question, tested with MailBody), listed and removed in
// Settings → General.

const PASSWORD = 'Deneme123*MailRemoteImagesPassword'

test('remote images: the setting, and senders whose images always load', async ({ browser }) => {
  test.slow()
  const context = await browser.newContext({ viewport: { width: 1400, height: 900 } })
  await registerAccount(context, newAccount('rimages', PASSWORD))
  const mail = await context.newPage()
  const signedIn = mail.waitForRequest((r) => new URL(r.url()).pathname.startsWith('/api/mail/') && !!r.headers().authorization)
  await mail.goto(appUrl('mail'))
  await expect(mail.getByRole('heading', { name: 'Inbox' })).toBeVisible({ timeout: 120_000 })
  const authorization = (await signedIn).headers().authorization
  await mail.goto(appUrl('mail', '/settings/general'))

  // Every sender: saved, and kept.
  const setting = mail.getByRole('combobox', { name: 'Load remote images' })
  await expect(setting).toHaveText('Ask each time', { timeout: 120_000 })
  await setting.click()
  await mail.getByRole('option', { name: 'Always' }).click()
  await expect(mail.getByText('Preference saved.')).toBeVisible({ timeout: 30_000 })
  await mail.reload()
  await expect(setting).toHaveText('Always', { timeout: 60_000 })

  // A sender chosen in the reader's question shows here, and goes.
  const senders = mail.getByRole('list', { name: 'Senders whose images always load' })
  await expect(mail.getByText('No senders yet.')).toBeVisible()
  const added = await mail.request.post(apiUrl('/mail/image-senders'), { headers: { authorization }, data: { address: 'Bulten@Example.org' } })
  expect(added.status()).toBe(204)
  await mail.reload()
  await expect(senders.getByText('bulten@example.org')).toBeVisible({ timeout: 60_000 })
  await senders.getByRole('button', { name: 'Remove bulten@example.org' }).click()
  await expect(mail.getByText('Images from bulten@example.org will be asked for again.')).toBeVisible({ timeout: 30_000 })
  await expect(mail.getByText('No senders yet.')).toBeVisible()
  await context.close()
})
