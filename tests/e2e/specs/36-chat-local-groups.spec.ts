import { expect, test } from '@playwright/test'
import { newAccount, registerAccount } from '../fixtures/apps'
import { acceptGroup, composer, createGroup, message, openChat, send } from '../fixtures/chat'

const PASSWORD = 'Deneme123*LocalGroupPassword'

// A server with no federation settings still has group chats: it makes its
// own identity and ordering key (crates/kutup-server/src/server_keys.rs) and
// orders groups whose members all live on it.
test('two people on one server with no federation settings share a group', async ({ browser }) => {
  test.slow()
  const tag = Date.now().toString(36)
  const alice = newAccount('grpalice', PASSWORD)
  const bob = newAccount('grpbob', PASSWORD)
  const contextA = await browser.newContext()
  const contextB = await browser.newContext()
  await registerAccount(contextA, alice)
  await registerAccount(contextB, bob)
  const pageA = await openChat(contextA)
  const pageB = await openChat(contextB)

  await pageA.getByRole('button', { name: 'New chat' }).first().click()
  await expect(pageA.getByRole('dialog').getByTestId('chat-create-group')).toBeVisible()
  await pageA.keyboard.press('Escape')

  const conversationId = await createGroup(pageA, bob.username, `Local ${tag}`)
  await expect(pageA.getByTestId(`chat-group-${conversationId}`)).toContainText(`Local ${tag}`, { timeout: 90_000 })
  await acceptGroup(pageB, conversationId)
  await expect(pageB.getByTestId(`chat-group-${conversationId}`)).toContainText(`Local ${tag}`)
  await expect(pageA.getByTestId('chat-group-delivery-readiness')).toHaveCount(0, { timeout: 90_000 })
  await expect(composer(pageA)).toBeVisible()

  const fromAlice = `local-group-from-alice-${tag}`
  await send(pageA, fromAlice)
  await expect(message(pageB, fromAlice)).toBeVisible({ timeout: 45_000 })
  const fromBob = `local-group-from-bob-${tag}`
  await send(pageB, fromBob)
  await expect(message(pageA, fromBob)).toBeVisible({ timeout: 45_000 })

  // The group and its history survive a reload on both sides.
  await pageA.reload()
  await pageB.reload()
  await expect(message(pageA, fromBob)).toBeVisible({ timeout: 90_000 })
  await expect(message(pageB, fromAlice)).toBeVisible({ timeout: 90_000 })

  await contextA.close()
  await contextB.close()
})
