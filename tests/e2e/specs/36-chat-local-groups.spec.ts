import { expect, test } from '@playwright/test'
import { newAccount, registerAccount } from '../fixtures/apps'
import {
  acceptGroup,
  befriend,
  closeDetails,
  composer,
  createGroup,
  message,
  openChat,
  openDetails,
  openGroup,
  send,
} from '../fixtures/chat'

const PASSWORD = 'Deneme123*LocalGroupPassword'

// Groups on one server (docs/plans/pairwise-groups.md): the group lives on
// its creator's server, its members are pseudonyms there, and messages go
// under each member's sender key. The basic UI of slice 1: create with
// contacts, join from the invitation, text both ways, rename, remove, leave.
test('three people on one server share a group, rename it, remove a member and leave', async ({ browser }) => {
  test.slow()
  const tag = Date.now().toString(36)
  const alice = newAccount('grpalice', PASSWORD)
  const bob = newAccount('grpbob', PASSWORD)
  const carol = newAccount('grpcarol', PASSWORD)
  const contextA = await browser.newContext()
  const contextB = await browser.newContext()
  const contextC = await browser.newContext()
  await registerAccount(contextA, alice)
  await registerAccount(contextB, bob)
  await registerAccount(contextC, carol)
  const pageA = await openChat(contextA)
  const pageB = await openChat(contextB)
  const pageC = await openChat(contextC)

  // Only contacts can be invited.
  await befriend(pageA, pageB, bob.username, alice.username)
  await befriend(pageA, pageC, carol.username, alice.username)

  const groupId = await createGroup(pageA, [bob.username, carol.username], `Local ${tag}`)
  await expect(pageA.getByTestId(`chat-group-${groupId}`)).toContainText(`Local ${tag}`, { timeout: 90_000 })
  // The invitation names who sent it, and joining opens the group.
  await openGroup(pageB, groupId)
  await expect(pageB.getByTestId('chat-group-invitation')).toContainText(`invited you to “Local ${tag}”`)
  await acceptGroup(pageB, groupId)
  await acceptGroup(pageC, groupId)
  await expect(pageB.getByTestId(`chat-group-${groupId}`)).toContainText(`Local ${tag}`)

  // Text both ways; nothing else is offered yet.
  const fromAlice = `local-group-from-alice-${tag}`
  await openGroup(pageA, groupId)
  await send(pageA, fromAlice)
  await expect(message(pageB, fromAlice)).toBeVisible({ timeout: 45_000 })
  await expect(message(pageC, fromAlice)).toBeVisible({ timeout: 45_000 })
  const fromBob = `local-group-from-bob-${tag}`
  await send(pageB, fromBob)
  await expect(message(pageA, fromBob)).toBeVisible({ timeout: 45_000 })
  await expect(message(pageC, fromBob)).toBeVisible({ timeout: 45_000 })
  await expect(pageA.getByRole('button', { name: 'Attach files' })).toHaveCount(0)

  // Alice renames it; the others see the new name.
  await openDetails(pageA)
  await expect(pageA.getByTestId('chat-group-members')).toContainText('3 members', { timeout: 45_000 })
  await pageA.getByTestId('chat-group-rename').click()
  await pageA.getByTestId('chat-group-title-input').fill(`Renamed ${tag}`)
  await pageA.getByTestId('chat-group-title-save').click()
  await expect(pageB.getByTestId(`chat-group-${groupId}`)).toContainText(`Renamed ${tag}`, { timeout: 90_000 })

  // Alice removes Carol: Carol's next message reaches nobody, and her group
  // says she may have been removed.
  await pageA
    .getByTestId('chat-group-members')
    .getByRole('button', { name: new RegExp(`^Remove ${carol.username}`) })
    .click()
  await expect(pageA.getByTestId('chat-group-members')).toContainText('2 members', { timeout: 45_000 })
  await closeDetails(pageA)
  const afterRemoval = `local-group-after-removal-${tag}`
  await send(pageA, afterRemoval)
  await expect(message(pageB, afterRemoval)).toBeVisible({ timeout: 45_000 })
  await pageC.reload()
  await openGroup(pageC, groupId)
  await expect(message(pageC, afterRemoval)).toHaveCount(0)
  await expect(pageC.getByTestId('chat-group-status')).toContainText('You may have been removed', { timeout: 90_000 })

  // The group and its history survive a reload.
  await pageA.reload()
  await pageB.reload()
  await openGroup(pageA, groupId)
  await openGroup(pageB, groupId)
  await expect(message(pageA, fromBob)).toBeVisible({ timeout: 90_000 })
  await expect(message(pageB, fromAlice)).toBeVisible({ timeout: 90_000 })

  // Bob leaves; the group says so on his side, and keeps going on Alice's.
  await openDetails(pageB)
  await pageB.getByTestId('chat-group-leave').click()
  await pageB.getByTestId('chat-group-leave-confirm').click()
  await closeDetails(pageB)
  await expect(composer(pageB)).toHaveCount(0, { timeout: 45_000 })
  await expect(pageB.getByText("You're no longer a member of this group.")).toBeVisible()
  await expect(composer(pageA)).toBeVisible()

  await contextA.close()
  await contextB.close()
  await contextC.close()
})
