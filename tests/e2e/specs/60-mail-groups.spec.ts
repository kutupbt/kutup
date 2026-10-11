import { expect, test, type BrowserContext, type Page } from '@playwright/test'
import { apiUrl, appUrl, newAccount, registerAccount, signInAsAdmin } from '../fixtures/apps'

// Mail groups (docs/plans/mail-groups.md): an administrator makes a shared
// mailbox and a distribution list in Account; the owner adds a member in
// Mail, which shares the mailbox's key from the browser; mail to the shared
// mailbox is read together and answered as it; list mail lands in each
// member's own inbox, labelled.

const PASSWORD = 'Deneme123*MailGroupsPassword'

async function openMail(context: BrowserContext): Promise<Page> {
  const page = await context.newPage()
  await page.goto(appUrl('mail'))
  await expect(page.getByRole('heading', { name: 'Inbox' })).toBeVisible({ timeout: 120_000 })
  return page
}

async function write(page: Page, to: string, subject: string, body: string) {
  await page.getByRole('button', { name: 'New message' }).first().click()
  const composer = page.getByRole('dialog', { name: 'New message' })
  // The To field: with shared mailboxes to write as, a From picker comes first.
  await composer.getByRole('combobox', { name: 'To' }).fill(to)
  await composer.getByRole('combobox', { name: 'To' }).press('Enter')
  await composer.getByRole('textbox', { name: 'Subject' }).fill(subject)
  await page.getByRole('textbox', { name: 'Message' }).fill(body)
  await page.getByRole('dialog', { name: subject }).getByRole('button', { name: 'Send', exact: true }).click()
  await expect(page.getByText('Message sent')).toBeVisible({ timeout: 60_000 })
}

test('a shared mailbox and a distribution list, made by an administrator and used in Mail', async ({ browser, request }) => {
  test.slow()
  const settings = (await (await request.get(apiUrl('/auth/settings'))).json()) as { chat: { serverName: string } }
  const domain = settings.chat.serverName
  const alice = newAccount('grpalice', PASSWORD)
  const bob = newAccount('grpbob', PASSWORD)
  const aliceContext = await browser.newContext()
  const bobContext = await browser.newContext()
  await registerAccount(aliceContext, alice)
  await registerAccount(bobContext, bob)
  // Mail makes each address key on first open.
  const aliceMail = await openMail(aliceContext)
  const bobMail = await openMail(bobContext)
  const tag = Date.now().toString(36)
  const hr = `hr${tag}`
  const team = `team${tag}`

  // The administrator creates both, with Alice as owner.
  const adminContext = await browser.newContext()
  await signInAsAdmin(adminContext)
  const admin = await adminContext.newPage()
  await admin.goto(appUrl('account', '/admin/mail/groups'))
  await expect(admin.getByRole('heading', { name: 'Mail groups' })).toBeVisible({ timeout: 60_000 })
  // The role addresses are there from the start.
  await expect(admin.getByText(`abuse@${domain}`)).toBeVisible()
  for (const [name, kind] of [
    [hr, 'Shared mailbox'],
    [team, 'Distribution list'],
  ] as const) {
    await admin.getByRole('button', { name: 'New group' }).click()
    const dialog = admin.getByRole('dialog', { name: 'New group' })
    await dialog.getByLabel('Name before the @').fill(name)
    await dialog.getByRole('combobox', { name: 'Kind' }).click()
    await admin.getByRole('option', { name: kind }).click()
    await dialog.getByRole('combobox', { name: 'Who may write to it' }).click()
    await admin.getByRole('option', { name: 'Kutup users of this server' }).click()
    await dialog.getByRole('textbox', { name: 'Add owner' }).fill(`${alice.username}@${domain}`)
    await dialog.getByRole('button', { name: 'Add owner' }).click()
    await expect(dialog.getByText(`${alice.username}@${domain}`)).toBeVisible()
    await dialog.getByRole('button', { name: 'New group' }).click()
    await expect(admin.getByText('Group created.')).toBeVisible({ timeout: 60_000 })
    await expect(admin.getByText(`${name}@${domain}`).first()).toBeVisible()
  }

  // Alice adds Bob to both from Mail (the shared mailbox's key goes to him).
  await aliceMail.goto(appUrl('mail', '/groups'))
  for (const name of [hr, team]) {
    const row = aliceMail.getByRole('listitem').filter({ hasText: `${name}@${domain}` })
    await row.getByRole('button', { name: 'Manage' }).click()
    const dialog = aliceMail.getByRole('dialog').filter({ hasText: `${name}@${domain}` })
    await dialog.getByRole('textbox', { name: 'Add member' }).fill(`${bob.username}@${domain}`)
    await dialog.getByRole('button', { name: 'Add member' }).click()
    await expect(dialog.getByText(`${bob.username}@${domain}`)).toBeVisible()
    if (name === hr) await dialog.getByRole('checkbox', { name: 'May send as it' }).click()
    await dialog.getByRole('button', { name: 'Save' }).click()
    await expect(aliceMail.getByText('Group saved.')).toBeVisible({ timeout: 60_000 })
  }

  // Bob writes to the shared mailbox; both members see it there.
  const subject = `Başvuru ${tag}`
  await write(bobMail, `${hr}@${domain}`, subject, 'Özgeçmişim ekte.')
  await aliceMail.goto(appUrl('mail', '/inbox'))
  await aliceMail.getByRole('link', { name: new RegExp(hr) }).first().click()
  const row = aliceMail.getByRole('link', { name: new RegExp(subject) })
  await expect(row).toBeVisible({ timeout: 60_000 })
  await row.click()
  await expect(aliceMail.frameLocator('iframe[title="Message"]').getByText('Özgeçmişim ekte.')).toBeVisible({ timeout: 60_000 })

  // Read for one, read for all.
  await bobMail.reload()
  await bobMail.getByRole('link', { name: new RegExp(hr) }).first().click()
  const bobRow = bobMail.getByRole('listitem').filter({ hasText: subject })
  await expect(bobRow).toBeVisible({ timeout: 60_000 })
  await expect(bobRow.locator('.font-semibold')).toHaveCount(0)

  // Alice answers as the mailbox.
  await aliceMail.getByRole('button', { name: 'Reply', exact: true }).click()
  const reply = aliceMail.getByRole('dialog', { name: `Re: ${subject}` })
  await expect(reply.getByRole('combobox', { name: 'From' })).toContainText(`${hr}@${domain}`)
  await aliceMail.getByRole('textbox', { name: 'Message' }).fill('Teşekkürler, inceliyoruz.')
  await reply.getByRole('button', { name: 'Send', exact: true }).click()
  await expect(aliceMail.getByText('Message sent')).toBeVisible({ timeout: 60_000 })
  await bobMail.goto(appUrl('mail', '/inbox'))
  const answer = bobMail.getByRole('link', { name: new RegExp(`Re: ${subject}`) })
  await expect(answer).toBeVisible({ timeout: 60_000 })
  await answer.click()
  await expect(bobMail.getByText(`${hr}@${domain}`).first()).toBeVisible()

  // List mail lands in Alice's own inbox, labelled with the list.
  const news = `Ekip haberi ${tag}`
  await write(bobMail, `${team}@${domain}`, news, 'Cuma toplantısı iptal.')
  await aliceMail.goto(appUrl('mail', '/inbox'))
  const listRow = aliceMail.getByRole('listitem').filter({ hasText: news })
  await expect(listRow).toBeVisible({ timeout: 60_000 })
  await expect(listRow.getByText(team)).toBeVisible()

  await adminContext.close()
  await aliceContext.close()
  await bobContext.close()
})
