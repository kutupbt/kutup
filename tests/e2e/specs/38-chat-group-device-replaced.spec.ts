import { expect, test } from '@playwright/test'
import { newAccount, registerAccount, signIn } from '../fixtures/apps'
import { acceptGroup, composer, createGroup, message, openChat, openChats, openGroup, openSettings, revokeOtherDevices, send } from '../fixtures/chat'

const PASSWORD = 'Deneme123*GroupDevicePassword'

// A member whose only Chat device is replaced (a new browser, the old one
// revoked; "Repair this browser" ends in the same state) is still a member of
// their groups: the group drops the dead device, admits the new one, and
// messages flow both ways again.
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

  const conversationId = await createGroup(pageA, bob.username, `Devices ${tag}`)
  await acceptGroup(pageB, conversationId)
  await expect(pageA.getByTestId('chat-group-delivery-readiness')).toHaveCount(0, { timeout: 90_000 })
  const before = `before-${tag}`
  await send(pageA, before)
  await expect(message(pageB, before)).toBeVisible({ timeout: 45_000 })
  const reply = `reply-${tag}`
  await send(pageB, reply)
  await expect(message(pageA, reply)).toBeVisible({ timeout: 45_000 })

  // Bob's browser is gone; he signs in on a new one and revokes the old.
  await contextB.close()
  const contextB2 = await browser.newContext()
  await signIn(contextB2, bob)
  const pageB2 = await openChat(contextB2)
  await revokeOtherDevices(pageB2, 1)

  // The group is still his, and it works in both directions.
  await openGroup(pageB2, conversationId)
  // Alice's Chat notices on its next device check (every two minutes).
  await expect(composer(pageB2)).toBeVisible({ timeout: 240_000 })
  const toNewDevice = `to-new-device-${tag}`
  await send(pageA, toNewDevice)
  await expect(message(pageB2, toNewDevice)).toBeVisible({ timeout: 90_000 })
  const fromNewDevice = `from-new-device-${tag}`
  await send(pageB2, fromNewDevice)
  await expect(message(pageA, fromNewDevice)).toBeVisible({ timeout: 90_000 })

  await contextA.close()
  await contextB2.close()
})

// The same through "Repair this browser", which Chat offers when it cannot
// open: the browser's device state is discarded and a fresh device
// registered. The old device is revoked without being asked for, Chat keeps
// opening while a group message it cannot read is waiting, and the group
// takes the new device in.
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

  const conversationId = await createGroup(pageA, bob.username, `Repair ${tag}`)
  await acceptGroup(pageB, conversationId)
  await expect(pageA.getByTestId('chat-group-delivery-readiness')).toHaveCount(0, { timeout: 90_000 })
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
  await openChats(pageB)

  // The device this browser was is gone from the account, unasked.
  await openSettings(pageB, 'Devices')
  await expect(pageB.getByTestId('chat-device-status')).toHaveAttribute('data-device-id', /^\d+$/, { timeout: 60_000 })
  await expect(pageB.locator('[data-testid^="chat-device-revoke-"]')).toHaveCount(0, { timeout: 60_000 })
  await openChats(pageB)

  // A message sent before the group has the new device cannot be read by
  // it, and must not stop Chat from opening again.
  const whileOutside = `while-outside-${tag}`
  await send(pageA, whileOutside)
  await expect(message(pageA, whileOutside)).toBeVisible({ timeout: 45_000 })
  await pageB.reload()
  await openGroup(pageB, conversationId)

  // Alice's Chat notices on its next device check (every two minutes).
  await expect(composer(pageB)).toBeVisible({ timeout: 240_000 })
  const toNewDevice = `to-new-device-${tag}`
  await send(pageA, toNewDevice)
  await expect(message(pageB, toNewDevice)).toBeVisible({ timeout: 90_000 })
  const fromNewDevice = `from-new-device-${tag}`
  await send(pageB, fromNewDevice)
  await expect(message(pageA, fromNewDevice)).toBeVisible({ timeout: 90_000 })

  await contextA.close()
  await contextB.close()
})
