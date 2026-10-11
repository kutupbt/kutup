import { expect, type Page } from '@playwright/test'
import { apiUrl } from './apps'

/**
 * `count` drafts named `<subject> 0…`, plus one saved from the composer
 * as `<subject>`: that draft's stored message, encrypted to the address
 * key, is the body of the rest (Mail open on the page). Returns the
 * page's `Authorization` header, for API checks.
 */
export async function seedDrafts(mail: Page, subject: string, count: number): Promise<string> {
  const saved = mail.waitForRequest((r) => r.method() === 'POST' && new URL(r.url()).pathname === '/api/mail/drafts')
  await mail.getByRole('button', { name: 'New message' }).first().click()
  await mail.getByRole('dialog', { name: 'New message' }).getByRole('textbox', { name: 'Subject' }).fill(subject)
  await mail.getByRole('textbox', { name: 'Message' }).fill('taslak')
  const draft = mail.getByRole('dialog', { name: subject })
  await expect(draft.getByText('Saved')).toBeVisible({ timeout: 30_000 })
  await draft.getByRole('button', { name: 'Close and keep the draft' }).click()
  const request = await saved
  const authorization = (await request.allHeaders()).authorization
  const first = (await (await request.response())!.json()) as { id: string; messageId: string }
  const domain = first.messageId.split('@')[1]
  const content = await (await mail.request.get(apiUrl(`/mail/messages/${first.id}/content`), { headers: { authorization } })).body()
  const tag = Date.now().toString(36)
  for (let i = 0; i < count; i++) {
    const response = await mail.request.post(apiUrl('/mail/drafts'), {
      headers: { authorization },
      multipart: {
        meta: { name: 'meta', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify({ subject: `${subject} ${i}`, messageId: `${tag}-${i}@${domain}` })) },
        body: { name: 'body', mimeType: 'application/octet-stream', buffer: content },
      },
    })
    expect(response.ok(), `${response.status()} ${await response.text()}`).toBe(true)
  }
  return authorization
}
