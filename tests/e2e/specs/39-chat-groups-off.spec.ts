// A server with CHAT_GROUPS=false offers direct chats only. Skips on a stack
// that offers groups.

import { expect, test } from '@playwright/test'
import { apiUrl, newAccount, registerAccount } from '../fixtures/apps'
import { acceptRequest, message, openChat, openConversationWith, openDirectChat, send } from '../fixtures/chat'

const PASSWORD = 'Deneme123*GroupsOffPassword'

test('with groups off, Chat offers direct chats only and they work', async ({ browser, request }) => {
  test.slow()
  const settings = (await (await request.get(apiUrl('/auth/settings'))).json()) as {
    chat: { serverName: string; mlsGroups: boolean; groupCalls: boolean }
  }
  test.skip(settings.chat.mlsGroups, 'this stack offers group chats (CHAT_GROUPS is on)')
  expect(settings.chat.groupCalls).toBe(false)

  const tag = Date.now()
  const alice = newAccount('offalice', PASSWORD)
  const bob = newAccount('offbob', PASSWORD)
  const contextA = await browser.newContext()
  const contextB = await browser.newContext()
  await registerAccount(contextA, alice)
  await registerAccount(contextB, bob)
  const pageA = await openChat(contextA)
  const pageB = await openChat(contextB)

  // Nothing offers a group.
  await pageA.getByRole('button', { name: 'New chat' }).first().click()
  await expect(pageA.getByRole('dialog').getByRole('button', { name: 'Note to Self' })).toBeVisible()
  await expect(pageA.getByRole('dialog').getByTestId('chat-create-group')).toHaveCount(0)
  await pageA.keyboard.press('Escape')

  // Direct chat, both ways.
  await openDirectChat(pageA, `${bob.username}@${settings.chat.serverName}`)
  const hello = `hello-${tag}`
  await send(pageA, hello)
  await openConversationWith(pageB, alice.username)
  await expect(message(pageB, hello)).toBeVisible({ timeout: 45_000 })
  await acceptRequest(pageB)
  const reply = `reply-${tag}`
  await send(pageB, reply)
  await expect(message(pageA, reply)).toBeVisible({ timeout: 45_000 })

  await contextA.close()
  await contextB.close()
})
