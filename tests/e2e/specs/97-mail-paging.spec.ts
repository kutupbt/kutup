import { expect, test } from '@playwright/test'
import { apiUrl, appUrl, newAccount, registerAccount } from '../fixtures/apps'

// Pages of the list (docs/plans/mail-parity.md, P3), as Proton's: previous,
// "page/pages" and next at the toolbar's end, numbered pages at the foot,
// the page in the address bar, the page size in Settings → General, and
// the selection pane beside the list.

const PASSWORD = 'Deneme123*MailPagingPassword'

test('the list pages as Proton: controls, address bar, page size, selection pane', async ({ browser }) => {
  test.slow()
  const context = await browser.newContext({ viewport: { width: 1400, height: 900 } })
  await registerAccount(context, newAccount('paging', PASSWORD))
  const mail = await context.newPage()
  await mail.goto(appUrl('mail'))
  await expect(mail.getByRole('heading', { name: 'Inbox' })).toBeVisible({ timeout: 120_000 })

  // One draft through the composer; its stored message, encrypted to the
  // address key, makes 50 more drafts.
  const tag = Date.now().toString(36)
  const saved = mail.waitForRequest((r) => r.method() === 'POST' && new URL(r.url()).pathname === '/api/mail/drafts')
  await mail.getByRole('button', { name: 'New message' }).first().click()
  await mail.getByRole('dialog', { name: 'New message' }).getByRole('textbox', { name: 'Subject' }).fill(`Sayfa ${tag}`)
  await mail.getByRole('textbox', { name: 'Message' }).fill('sayfalar')
  const draft = mail.getByRole('dialog', { name: `Sayfa ${tag}` })
  await expect(draft.getByText('Saved')).toBeVisible({ timeout: 30_000 })
  await draft.getByRole('button', { name: 'Close and keep the draft' }).click()
  const request = await saved
  const authorization = (await request.allHeaders()).authorization
  const first = (await (await request.response())!.json()) as { id: string; messageId: string }
  const domain = first.messageId.split('@')[1]
  const content = await (await mail.request.get(apiUrl(`/mail/messages/${first.id}/content`), { headers: { authorization } })).body()
  for (let i = 0; i < 50; i++) {
    const response = await mail.request.post(apiUrl('/mail/drafts'), {
      headers: { authorization },
      multipart: {
        meta: { name: 'meta', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify({ subject: `Sayfa ${tag} ${i}`, messageId: `${tag}-${i}@${domain}` })) },
        body: { name: 'body', mimeType: 'application/octet-stream', buffer: content },
      },
    })
    expect(response.ok(), `${response.status()} ${await response.text()}`).toBe(true)
  }

  await mail.getByRole('link', { name: /^Drafts( \d+)?$/ }).click()
  const rows = mail.getByRole('link', { name: new RegExp(`Sayfa ${tag}`) })
  await expect(rows).toHaveCount(50, { timeout: 30_000 })
  await expect(mail.getByRole('button', { name: 'Page 1 of 2' })).toHaveText('1/2')
  const pane = mail.getByRole('region', { name: 'Selection pane' })
  await expect(pane).toContainText('You have 51 conversations stored in this folder')
  const foot = mail.getByRole('navigation', { name: 'Pages' })
  await expect(foot.getByRole('button', { name: 'Go to page 1' })).toHaveAttribute('aria-current', 'page')

  // Next: the second page, in the address bar; next is off at the end.
  await mail.getByRole('button', { name: 'Next page', exact: true }).click()
  await expect(mail).toHaveURL(/[?&]page=2/)
  await expect(rows).toHaveCount(1)
  await expect(mail.getByRole('button', { name: 'Page 2 of 2' })).toBeVisible()
  await expect(mail.getByRole('button', { name: 'Next page', exact: true })).toBeDisabled()
  // A reload keeps the page.
  await mail.reload()
  await expect(rows).toHaveCount(1, { timeout: 60_000 })
  // Back from the foot; the dropdown picks a page too.
  await foot.getByRole('button', { name: 'Go to page 1' }).click()
  await expect(rows).toHaveCount(50)
  await expect(mail).not.toHaveURL(/page=/)
  await mail.getByRole('button', { name: 'Page 1 of 2' }).click()
  await mail.getByRole('menuitemradio', { name: 'Page 2' }).click()
  await expect(rows).toHaveCount(1)

  // Checked rows: the pane says how many, and clears them.
  await mail.getByRole('checkbox', { name: new RegExp(`Select “Sayfa ${tag}`) }).first().check({ force: true })
  await expect(pane).toContainText('You selected 1 conversation from this folder')
  await pane.getByRole('button', { name: 'Clear selection' }).click()
  await expect(pane).toContainText('You have 51 conversations stored in this folder')

  // A page of 100: one page, no foot.
  await mail.goto(appUrl('mail', '/settings/general'))
  await mail.getByRole('combobox', { name: 'Conversations per page' }).click()
  await mail.getByRole('option', { name: '100' }).click()
  await expect(mail.getByText('Preference saved.')).toBeVisible({ timeout: 30_000 })
  await mail.goto(appUrl('mail', '/drafts'))
  await expect(rows).toHaveCount(51, { timeout: 60_000 })
  await expect(mail.getByRole('button', { name: 'Page 1 of 1' })).toBeDisabled()
  await expect(mail.getByRole('navigation', { name: 'Pages' })).toHaveCount(0)
  await context.close()
})
