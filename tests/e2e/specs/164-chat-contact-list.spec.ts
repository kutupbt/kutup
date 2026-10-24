import { expect, test } from '@playwright/test'
import { newAccount, registerAccount, signIn } from '../fixtures/apps'
import {
  backupCursor,
  closeDetails,
  message,
  openChat,
  openConversationWith,
  openDetails,
  openDirectChat,
  send,
  waitForProtection,
} from '../fixtures/chat'

const PASSWORD = 'Deneme123*ContactListPassword'

// The account's Chat contact list (docs/plans/chat-contacts-sync.md): a block
// is written to it at once on the web, so it holds on a new browser after
// the only one was lost. The new browser reads the list before it takes any
// message, so nothing from the blocked person is taken first.
test('a block made before the only browser was lost still holds on a new one', async ({ browser }) => {
  test.slow()
  const tag = Date.now().toString(36)
  const alice = newAccount('listalice', PASSWORD)
  const carol = newAccount('listcarol', PASSWORD)
  const contextA = await browser.newContext()
  const contextC = await browser.newContext()
  await registerAccount(contextA, alice)
  await registerAccount(contextC, carol)
  const pageA = await openChat(contextA)
  const pageC = await openChat(contextC)

  // Carol writes; Alice blocks her from the request.
  const cursorBefore = await backupCursor(pageA)
  await openDirectChat(pageC, alice.username)
  const first = `first-${tag}`
  await send(pageC, first)
  await openConversationWith(pageA, carol.username)
  await expect(message(pageA, first)).toBeVisible({ timeout: 45_000 })
  await openDetails(pageA)
  await pageA.getByRole('button', { name: /^Block / }).click()
  await expect(pageA.getByRole('button', { name: 'Unblock', exact: true }).first()).toBeVisible({ timeout: 30_000 })
  await closeDetails(pageA)
  // Carol's message is in Alice's history backup before her browser goes,
  // so the new one restores the conversation.
  await waitForProtection(pageA, cursorBefore)

  // Alice's only browser is gone; she signs in on a new one, which starts
  // her Chat over (she has no other device to link it from): the old device
  // leaves the account with it.
  await contextA.close()
  const contextA2 = await browser.newContext()
  await signIn(contextA2, alice)
  const pageA2 = await openChat(contextA2)

  // Carol writes again. The new browser has Carol blocked, from the list:
  // her conversation offers Unblock, and her new message never shows.
  // With sealed sender the block also replaced Alice's delivery key, so the
  // send may be refused before it reaches her; without it, the new browser
  // takes and discards it. Either way it never shows.
  const second = `second-${tag}`
  await send(pageC, second)
  // The conversation is back with the history; a blocked one has no composer.
  await openConversationWith(pageA2, carol.username)
  await expect(pageA2.getByRole('link', { name: new RegExp(carol.username) }).first()).toContainText('Blocked')
  await expect(pageA2.getByRole('button', { name: 'Unblock', exact: true }).first()).toBeVisible({ timeout: 45_000 })
  await expect(pageA2.getByRole('button', { name: 'Accept', exact: true })).toHaveCount(0)
  // Time for anything still on its way to arrive (and be discarded).
  await pageA2.waitForTimeout(5_000)
  await expect(message(pageA2, second)).toHaveCount(0)

  await contextA2.close()
  await contextC.close()
})
