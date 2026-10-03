// Media in a direct chat on one server whose identity the server made for
// itself (no FEDERATION_* settings), once its operator has provisioned
// sealed sender. Without sealed sender a direct chat has no attach button,
// so this skips on a stack that does not offer it.

import { expect, test, type Page } from '@playwright/test'
import { apiUrl, newAccount, registerAccount } from '../fixtures/apps'
import { acceptRequest, message, openChat, openConversationWith, openDirectChat, send, sendAttachment } from '../fixtures/chat'

const PASSWORD = 'Deneme123*DirectMediaPassword'

function attachmentIn(page: Page, filename: string) {
  return page.getByTestId('chat-message').filter({ hasText: filename }).getByText(filename, { exact: true })
}

test('two people on one server exchange an attachment in a direct chat', async ({ browser, request }) => {
  test.slow()
  const settings = (await (await request.get(apiUrl('/auth/settings'))).json()) as {
    chat: { serverName: string; sealedSender: boolean }
  }
  test.skip(!settings.chat.sealedSender, 'this stack has no sealed sender policy (docs/self-hosting.md)')

  const tag = Date.now()
  const alice = newAccount('mediaalice', PASSWORD)
  const bob = newAccount('mediabob', PASSWORD)
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
})
