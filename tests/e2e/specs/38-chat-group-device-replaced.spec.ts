import { expect, test } from '@playwright/test'
import { newAccount, registerAccount, signIn } from '../fixtures/apps'
import { acceptGroup, befriend, composer, createGroup, message, openChat, openChats, openGroup, openSettings, send, startOver } from '../fixtures/chat'

const PASSWORD = 'Deneme123*GroupDevicePassword'

// A member whose only Chat device is replaced (a new browser, the old one
// revoked; "Repair this browser" ends in the same state) is still a member of
// their groups (docs/plans/pairwise-groups.md §5). Here the old device goes
// within minutes of joining, before its group-list entry was written: the
// member's binding is their account's, so the others still send to them; the
// next message gives the new device the group's key with its sender's, and
// the device finds the account's place again (its pseudonym is derived from
// the account key), so messages flow both ways.
test('a group member keeps the group after replacing their only device', async ({ browser }) => {
  test.slow()
  const tag = Date.now().toString(36)
  const alice = newAccount('devalice', PASSWORD)
  const bob = newAccount('devbob', PASSWORD)
  const contextA = await browser.newContext()
  const contextB = await browser.newContext()
  await registerAccount(contextA, alice)
  await registerAccount(contextB, bob)
  const pageA = await openChat(contextA)
  const pageB = await openChat(contextB)

  await befriend(pageA, pageB, bob.username, alice.username)
  const conversationId = await createGroup(pageA, bob.username, `Devices ${tag}`)
  await acceptGroup(pageB, conversationId)
  const before = `before-${tag}`
  await send(pageA, before)
  await expect(message(pageB, before)).toBeVisible({ timeout: 45_000 })
  const reply = `reply-${tag}`
  await send(pageB, reply)
  await expect(message(pageA, reply)).toBeVisible({ timeout: 45_000 })

  // Bob's browser is gone; he signs in on a new one, which starts his Chat
  // over (no other device to link it from): the old device leaves the
  // account, and his groups stay with the account.
  await contextB.close()
  const contextB2 = await browser.newContext()
  await signIn(contextB2, bob)
  const pageB2 = await openChat(contextB2)

  // Alice writes; the new device takes the group up from her message and
  // reads it.
  const toNewDevice = `to-new-device-${tag}`
  await send(pageA, toNewDevice)
  await openGroup(pageB2, conversationId)
  await expect(composer(pageB2)).toBeVisible({ timeout: 120_000 })
  await expect(message(pageB2, toNewDevice)).toBeVisible({ timeout: 90_000 })
  const fromNewDevice = `from-new-device-${tag}`
  await send(pageB2, fromNewDevice)
  await expect(message(pageA, fromNewDevice)).toBeVisible({ timeout: 90_000 })

  await contextA.close()
  await contextB2.close()
})

// The same through "Repair this browser", which Chat offers when it cannot
// open: the browser's device state is discarded and a fresh device
// registered. The old device is revoked without being asked for, and the
// next group message gives the new device the group again, as above.
test('a group member keeps the group after repairing their browser', async ({ browser }) => {
  test.slow()
  const tag = Date.now().toString(36)
  const alice = newAccount('repalice', PASSWORD)
  const bob = newAccount('repbob', PASSWORD)
  const contextA = await browser.newContext()
  const contextB = await browser.newContext()
  await registerAccount(contextA, alice)
  await registerAccount(contextB, bob)
  const pageA = await openChat(contextA)
  const pageB = await openChat(contextB)

  await befriend(pageA, pageB, bob.username, alice.username)
  const conversationId = await createGroup(pageA, bob.username, `Repair ${tag}`)
  await acceptGroup(pageB, conversationId)
  const before = `before-${tag}`
  await send(pageA, before)
  await expect(message(pageB, before)).toBeVisible({ timeout: 45_000 })

  // Chat cannot open on this browser's state (the server answers, but no
  // longer knows what the browser asks about), and Bob takes the repair it
  // offers. A server that is merely unreachable offers none
  // (40-chat-open-failures).
  await pageB.route('**/api/chat/messages*', (route) => route.fulfill({ status: 404, body: '' }))
  await pageB.reload()
  await expect(pageB.getByText('Chat could not open')).toBeVisible({ timeout: 90_000 })
  await pageB.getByRole('button', { name: 'Repair this browser' }).click()
  await pageB.unroute('**/api/chat/messages*')
  await pageB.getByRole('button', { name: 'Reset and restore' }).click()
  // The account's identity was only on this browser's discarded device:
  // with no other device to link from, Bob starts over.
  await startOver(pageB)
  await openChats(pageB)

  // The device this browser was is gone from the account, unasked.
  await openSettings(pageB, 'Linked devices')
  await expect(pageB.getByTestId('chat-device-status')).toHaveAttribute('data-device-id', /^\d+$/, { timeout: 60_000 })
  await expect(pageB.locator('[data-testid^="chat-device-revoke-"]')).toHaveCount(0, { timeout: 60_000 })
  await openChats(pageB)

  // Alice's next message brings the group back to the new device, and must
  // not stop Chat from opening again whatever happens to it.
  const whileOutside = `while-outside-${tag}`
  await send(pageA, whileOutside)
  await expect(message(pageA, whileOutside)).toBeVisible({ timeout: 45_000 })
  await pageB.reload()
  await openGroup(pageB, conversationId)

  await expect(composer(pageB)).toBeVisible({ timeout: 120_000 })
  await expect(message(pageB, whileOutside)).toBeVisible({ timeout: 90_000 })
  const toNewDevice = `to-new-device-${tag}`
  await send(pageA, toNewDevice)
  await expect(message(pageB, toNewDevice)).toBeVisible({ timeout: 90_000 })
  const fromNewDevice = `from-new-device-${tag}`
  await send(pageB, fromNewDevice)
  await expect(message(pageA, fromNewDevice)).toBeVisible({ timeout: 90_000 })

  await contextA.close()
  await contextB.close()
})
