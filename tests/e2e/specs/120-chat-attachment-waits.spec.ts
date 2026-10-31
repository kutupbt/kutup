// An attachment message waits for the recipient's server to store its copy
// before it is sent (docs/plans/federation-outbox.md, Signal's model): it
// shows as sending meanwhile, the wait outlives a reload, and a refusal shows
// it as not delivered, with a retry. The recipient never gets the message
// before its copy is stored. The server's answers are held back here by
// intercepting this browser's delivery requests: `queued` as when the
// recipient's server is down, and a refusal as when it refuses for good.

import { expect, test, type Page, type Route } from '@playwright/test'
import { apiUrl, newAccount, registerAccount } from '../fixtures/apps'
import { acceptRequest, message, openChat, openConversationWith, openDirectChat, send } from '../fixtures/chat'

const PASSWORD = 'Deneme123*AttachmentWaitPassword'
const DELIVERIES = '**/api/chat/media/deliveries'

interface Settings {
  chat: { serverName: string; sealedSender: boolean }
}

function attachmentIn(page: Page, filename: string) {
  return page.getByTestId('chat-message').filter({ hasText: filename })
}

async function attach(page: Page, filename: string): Promise<void> {
  await page.getByTestId('chat-attachment-input').setInputFiles({
    name: filename,
    mimeType: 'text/plain',
    buffer: Buffer.from(`contents of ${filename}`, 'utf8'),
  })
}

/** Answers this browser's delivery requests with `answer` instead of the server. */
async function holdDeliveries(page: Page, answer: (operationId: string) => { status: number; body: unknown }) {
  await page.route(DELIVERIES, async (route: Route) => {
    const { operationId } = route.request().postDataJSON() as { operationId: string }
    const { status, body } = answer(operationId)
    await route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) })
  })
}

test('an attachment waits for the copy, outlives a reload, and is retried after a refusal', async ({ browser, request }) => {
  test.slow()
  const settings = (await (await request.get(apiUrl('/auth/settings'))).json()) as Settings
  test.skip(!settings.chat.sealedSender, 'this stack has no sealed sender policy (docs/self-hosting.md)')
  const tag = Date.now()
  const alice = newAccount('waitalice', PASSWORD)
  const bob = newAccount('waitbob', PASSWORD)
  const contextA = await browser.newContext()
  const contextB = await browser.newContext()
  await registerAccount(contextA, alice)
  await registerAccount(contextB, bob)
  const pageA = await openChat(contextA)
  const pageB = await openChat(contextB)

  await openDirectChat(pageA, `${bob.username}@${settings.chat.serverName}`)
  await send(pageA, `hello-${tag}`)
  await openConversationWith(pageB, alice.username)
  await expect(message(pageB, `hello-${tag}`)).toBeVisible({ timeout: 45_000 })
  await acceptRequest(pageB)
  await send(pageB, `reply-${tag}`)
  await expect(message(pageA, `reply-${tag}`)).toBeVisible({ timeout: 45_000 })
  await expect(pageA.getByTestId('chat-attachment-button')).toBeEnabled({ timeout: 45_000 })

  // Queued: the message shows, sending, and goes nowhere.
  const queued = `queued-${tag}.txt`
  let asked = 0
  await holdDeliveries(pageA, (operationId) => {
    asked += 1
    return { status: 200, body: { operationId, status: 'queued' } }
  })
  await attach(pageA, queued)
  await expect(attachmentIn(pageA, queued)).toBeVisible({ timeout: 45_000 })
  await expect(attachmentIn(pageA, queued).getByTestId('chat-receipt-sending')).toBeVisible()
  await expect.poll(() => asked, { timeout: 30_000 }).toBeGreaterThan(0)
  // Past the "not sent" grace of other messages: still sending, not failed.
  await pageA.waitForTimeout(35_000)
  await expect(attachmentIn(pageA, queued).getByTestId('chat-receipt-sending')).toBeVisible()
  await expect(attachmentIn(pageA, queued).getByTestId('chat-send-retry')).toHaveCount(0)
  await expect(attachmentIn(pageB, queued)).toHaveCount(0)

  // The page reloads with the server answering again: the wait it kept
  // sends the message, though nothing asked to send it after the reload.
  await pageA.unroute(DELIVERIES)
  await pageA.reload()
  await expect(attachmentIn(pageB, queued)).toBeVisible({ timeout: 90_000 })
  await expect(attachmentIn(pageA, queued).getByTestId('chat-receipt-sending')).toHaveCount(0, { timeout: 45_000 })

  // Refused for good: not delivered at once, and never to the recipient.
  const refused = `refused-${tag}.txt`
  await holdDeliveries(pageA, () => ({
    status: 422,
    body: { error: "the recipient's server refused the attachment" },
  }))
  await attach(pageA, refused)
  const notDelivered = attachmentIn(pageA, refused).getByTestId('chat-media-not-delivered')
  await expect(notDelivered).toBeVisible({ timeout: 45_000 })
  await expect(notDelivered).toHaveAttribute('data-reason', 'refused')
  await expect(attachmentIn(pageB, refused)).toHaveCount(0)

  // Retried once the server takes it: delivered.
  await pageA.unroute(DELIVERIES)
  await notDelivered.click()
  await expect(attachmentIn(pageB, refused)).toBeVisible({ timeout: 90_000 })
  await expect(attachmentIn(pageA, refused).getByTestId('chat-media-not-delivered')).toHaveCount(0)

  await contextA.close()
  await contextB.close()
})
