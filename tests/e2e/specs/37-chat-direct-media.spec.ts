// Media in a direct chat on one server whose identity the server made for
// itself (no FEDERATION_* settings): it travels by sealed delivery, which the
// server provisions for itself. Without sealed sender a direct chat has no
// attach button, so this skips on a stack that does not offer it. Closing
// federation decides only whether other servers can be reached; it must not
// switch sealed delivery off on the server itself.

import { expect, test, type Browser, type Page } from '@playwright/test'
import { apiUrl, appUrl, newAccount, registerAccount, signInAsAdmin } from '../fixtures/apps'
import { acceptRequest, message, openChat, openConversationWith, openDirectChat, send, sendAttachment } from '../fixtures/chat'

const PASSWORD = 'Deneme123*DirectMediaPassword'

function attachmentIn(page: Page, filename: string) {
  return page.getByTestId('chat-message').filter({ hasText: filename }).getByText(filename, { exact: true })
}

interface Settings {
  chat: { serverName: string; sealedSender: boolean; federation: boolean }
}

async function chatSettings(request: { get(url: string): Promise<{ json(): Promise<unknown> }> }): Promise<Settings> {
  return (await (await request.get(apiUrl('/auth/settings'))).json()) as Settings
}

/** Two new people exchange a message and then a file each way. */
async function exchangeAttachments(browser: Browser, settings: Settings, prefix: string) {
  const tag = Date.now()
  const alice = newAccount(`${prefix}alice`, PASSWORD)
  const bob = newAccount(`${prefix}bob`, PASSWORD)
  const contextA = await browser.newContext()
  const contextB = await browser.newContext()
  await registerAccount(contextA, alice)
  await registerAccount(contextB, bob)
  const pageA = await openChat(contextA)
  const pageB = await openChat(contextB)

  // A first message is a request; media waits until it is accepted.
  await openDirectChat(pageA, `${bob.username}@${settings.chat.serverName}`)
  await expect(pageA.getByTestId('chat-attachment-input')).toHaveCount(0)
  const first = `hello-${tag}`
  await send(pageA, first)
  await openConversationWith(pageB, alice.username)
  await expect(message(pageB, first)).toBeVisible({ timeout: 45_000 })
  await acceptRequest(pageB)
  const reply = `reply-${tag}`
  await send(pageB, reply)
  await expect(message(pageA, reply)).toBeVisible({ timeout: 45_000 })

  // Both directions.
  const fromAlice = `from-alice-${tag}.txt`
  await expect(pageA.getByTestId('chat-attachment-button')).toBeEnabled({ timeout: 45_000 })
  await sendAttachment(pageA, fromAlice, `alice's file ${tag}`)
  await expect(attachmentIn(pageB, fromAlice)).toBeVisible({ timeout: 90_000 })

  const fromBob = `from-bob-${tag}.txt`
  await expect(pageB.getByTestId('chat-attachment-button')).toBeEnabled({ timeout: 45_000 })
  await sendAttachment(pageB, fromBob, `bob's file ${tag}`)
  await expect(attachmentIn(pageA, fromBob)).toBeVisible({ timeout: 90_000 })

  await contextA.close()
  await contextB.close()
}

/** Turn federation on or off with the administrator's switch. */
async function setFederation(page: Page, on: boolean) {
  await page.goto(appUrl('account', '/admin/federation'))
  const toggle = page.locator('#federation-global')
  await expect(toggle).toBeVisible({ timeout: 30_000 })
  if ((await toggle.getAttribute('data-state')) !== (on ? 'checked' : 'unchecked')) {
    await toggle.click()
  }
  await expect(toggle).toHaveAttribute('data-state', on ? 'checked' : 'unchecked', { timeout: 30_000 })
}

test('two people on one server exchange an attachment in a direct chat', async ({ browser, request }) => {
  test.slow()
  const settings = await chatSettings(request)
  test.skip(!settings.chat.sealedSender, 'this stack has no sealed sender policy (docs/self-hosting.md)')
  await exchangeAttachments(browser, settings, 'media')
})

test('closing federation leaves attachments in direct chats on the server working', async ({ browser, request }) => {
  test.slow()
  const before = await chatSettings(request)
  test.skip(!before.chat.sealedSender, 'this stack has no sealed sender policy (docs/self-hosting.md)')
  const adminContext = await browser.newContext()
  await signInAsAdmin(adminContext)
  const admin = await adminContext.newPage()
  try {
    await setFederation(admin, false)
    await expect.poll(async () => (await chatSettings(request)).chat.federation, { timeout: 30_000 }).toBe(false)
    const closed = await chatSettings(request)
    expect(closed.chat.sealedSender).toBe(true)
    await exchangeAttachments(browser, closed, 'closedfed')
  } finally {
    await setFederation(admin, true)
    await adminContext.close()
  }
})
