import { expect, test, type Page } from '@playwright/test'
import { newAccount, registerAccount, signIn } from '../fixtures/apps'
import {
  befriend,
  closeDetails,
  message,
  openChat,
  openChats,
  openConversationWith,
  openDetails,
  openSettings,
  send,
} from '../fixtures/chat'

const PASSWORD = 'Deneme123*AccountIdentityPassword'

/** The thread's "safety number changed" lines for `name`. */
function changedLines(page: Page, name: string) {
  return page.getByText(`Your safety number with ${name} changed.`)
}

/** Bob marks Alice verified after comparing the numbers (Signal's "Mark as verified"). */
async function markVerified(page: Page) {
  await openDetails(page)
  await page.getByTestId('chat-safety-open').click()
  const dialog = page.getByRole('dialog')
  await dialog.getByTestId('chat-safety-mark-verified').click()
  await expect(dialog.getByTestId('chat-safety-clear-verified')).toBeVisible({ timeout: 30_000 })
  await page.keyboard.press('Escape')
  await expect(page.getByText('You have verified this safety number.')).toBeVisible()
  await closeDetails(page)
}

/**
 * One Chat identity per account, as Signal's (docs/plans/account-identity-key.md):
 * a second browser is linked with the code the first one is given, which
 * changes nothing for contacts; both send and receive; removing a lost device
 * with "reset identity" keeps the account's other device and shows the
 * contact one "safety number changed" and clears their verification; a
 * cleared browser with no other device starts over.
 */
test('links a device, resets the identity on removal, and starts over in a cleared browser', async ({ browser }) => {
  test.slow()
  const tag = Date.now().toString(36)
  const alice = newAccount('idalice', PASSWORD)
  const bob = newAccount('idbob', PASSWORD)
  const contextA = await browser.newContext()
  const contextB = await browser.newContext()
  await registerAccount(contextA, alice)
  await registerAccount(contextB, bob)
  const pageA = await openChat(contextA)
  const pageB = await openChat(contextB)
  await befriend(pageA, pageB, bob.username, alice.username)

  // Alice's second browser is linked from her first with its code.
  const contextA2 = await browser.newContext()
  await signIn(contextA2, alice)
  const pageA2 = await openChat(contextA2, 'primary', undefined, { linkFrom: pageA })
  // Both are devices of the account, the first listed on the second.
  await openSettings(pageA2, 'Linked devices')
  await expect(pageA2.locator('[data-testid^="chat-device-revoke-"]')).toHaveCount(1, { timeout: 45_000 })
  await openChats(pageA2)

  // Both of Alice's browsers write to Bob and read his answer; Bob's thread
  // shows no change of safety number for a linked device.
  const fromFirst = `from-first-${tag}`
  const fromSecond = `from-second-${tag}`
  await openConversationWith(pageA, bob.username)
  await send(pageA, fromFirst)
  await openConversationWith(pageA2, bob.username)
  await send(pageA2, fromSecond)
  await openConversationWith(pageB, alice.username)
  await expect(message(pageB, fromFirst)).toBeVisible({ timeout: 60_000 })
  await expect(message(pageB, fromSecond)).toBeVisible({ timeout: 60_000 })
  const answer = `answer-${tag}`
  await send(pageB, answer)
  await expect(message(pageA, answer)).toBeVisible({ timeout: 60_000 })
  await expect(message(pageA2, answer)).toBeVisible({ timeout: 60_000 })
  await expect(changedLines(pageB, alice.username)).toHaveCount(0)

  // Bob verifies Alice.
  await markVerified(pageB)

  // Alice's second browser is lost: her first removes it and resets her
  // identity (the default for a removal).
  await contextA2.close()
  await openSettings(pageA, 'Linked devices')
  const removeButton = pageA.locator('[data-testid^="chat-device-revoke-"]')
  await expect(removeButton).toHaveCount(1, { timeout: 45_000 })
  await removeButton.click()
  const confirm = pageA.getByRole('alertdialog')
  await expect(confirm.getByTestId('chat-device-reset-identity')).toBeChecked()
  await confirm.getByRole('button', { name: 'Remove and reset identity', exact: true }).click()
  await expect(removeButton).toHaveCount(0, { timeout: 60_000 })
  await openChats(pageA)

  // Alice writes under her new identity: Bob reads it, sees the safety
  // number changed once, and Alice is no longer verified for him.
  const afterReset = `after-reset-${tag}`
  await openConversationWith(pageA, bob.username)
  await send(pageA, afterReset)
  await expect(message(pageB, afterReset)).toBeVisible({ timeout: 90_000 })
  await expect(changedLines(pageB, alice.username)).toHaveCount(1, { timeout: 60_000 })
  await openDetails(pageB)
  await expect(pageB.getByText('You have verified this safety number.')).toHaveCount(0)
  await closeDetails(pageB)
  const replyAfterReset = `reply-after-reset-${tag}`
  await send(pageB, replyAfterReset)
  await expect(message(pageA, replyAfterReset)).toBeVisible({ timeout: 60_000 })

  // Alice's last browser is cleared too: with no device to link from, she
  // starts over in a new one, which restores her history.
  await contextA.close()
  const contextA3 = await browser.newContext()
  await signIn(contextA3, alice)
  const pageA3 = await openChat(contextA3)
  await openConversationWith(pageA3, bob.username)
  await expect(message(pageA3, replyAfterReset)).toBeVisible({ timeout: 90_000 })
  const afterStartOver = `after-start-over-${tag}`
  await send(pageA3, afterStartOver)
  await expect(message(pageB, afterStartOver)).toBeVisible({ timeout: 90_000 })
  await expect(changedLines(pageB, alice.username)).toHaveCount(2, { timeout: 60_000 })

  await contextA3.close()
  await contextB.close()
})
