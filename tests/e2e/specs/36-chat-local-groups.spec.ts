import { expect, test } from '@playwright/test'
import { newAccount, registerAccount, signIn } from '../fixtures/apps'
import {
  acceptGroup,
  befriend,
  closeDetails,
  composer,
  createGroup,
  message,
  openChat,
  openDetails,
  openConversationWith,
  openDirectChat,
  openGroup,
  removeGroupMember,
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
  // The title someone else chose is its own direction-isolated run.
  await expect(pageB.getByTestId('chat-group-invitation')).toContainText(`invited you to “\u2068Local ${tag}\u2069”`)
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
  await removeGroupMember(pageA, carol.username)
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

// An invitation from someone this browser has no contact with is a message
// request (Signal's rule). Today that happens after the invitee lost every
// browser: contact states don't come back with the history yet
// (docs/roadmap.md), while the inviter still has them as a contact. Decline
// turns one invitation down; Block stops every invitation of theirs.
test('an invitation from someone not in contacts is a request: decline one, block them all', async ({ browser }) => {
  test.slow()
  const tag = Date.now().toString(36)
  const alice = newAccount('reqalice', PASSWORD)
  const dave = newAccount('reqdave', PASSWORD)
  const erin = newAccount('reqerin', PASSWORD)
  const contextA = await browser.newContext()
  const contextD = await browser.newContext()
  const contextE = await browser.newContext()
  await registerAccount(contextA, alice)
  await registerAccount(contextD, dave)
  await registerAccount(contextE, erin)
  const pageA = await openChat(contextA)
  const firstD = await openChat(contextD)
  const pageE = await openChat(contextE)
  await befriend(pageA, firstD, dave.username, alice.username)

  // Dave's browser is lost; a clean one signs in and has no contacts.
  await contextD.close()
  const restoredD = await browser.newContext()
  await signIn(restoredD, dave)
  const pageD = await openChat(restoredD)

  // The first invitation is a request, by the name and the address; Decline
  // turns it down, and it is gone.
  const declined = await createGroup(pageA, dave.username, `Declined ${tag}`)
  await openGroup(pageD, declined)
  const invitation = pageD.getByTestId('chat-group-invitation')
  await expect(invitation).toContainText("isn't in your contacts")
  // Her address is shown: as her name (no profile known here), or beside it.
  await expect(invitation).toContainText(alice.username)
  await invitation.getByRole('button', { name: 'Decline' }).click()
  await expect(pageD.getByTestId(`chat-group-${declined}`)).toHaveCount(0, { timeout: 45_000 })

  // The second one: Block. It goes, and nothing more of Alice's comes.
  const blocked = await createGroup(pageA, dave.username, `Blocked ${tag}`)
  await openGroup(pageD, blocked)
  await pageD.getByTestId('chat-group-invitation').getByRole('button', { name: 'Block' }).click()
  await expect(pageD.getByTestId(`chat-group-${blocked}`)).toHaveCount(0, { timeout: 45_000 })
  const after = await createGroup(pageA, dave.username, `After ${tag}`)
  // Only once something sent later has arrived is the absence checked: a
  // stranger's message to Dave, sent after Alice's invitation.
  const probe = `request-probe-${tag}`
  await openDirectChat(pageE, dave.username)
  await send(pageE, probe)
  await openConversationWith(pageD, erin.username)
  await expect(message(pageD, probe)).toBeVisible({ timeout: 60_000 })
  await expect(pageD.getByTestId(`chat-group-${after}`)).toHaveCount(0)

  await contextA.close()
  await restoredD.close()
  await contextE.close()
})
