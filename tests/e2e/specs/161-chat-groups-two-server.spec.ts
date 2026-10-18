import { expect, test } from '@playwright/test'
import { apiUrl, hasSecondaryServer, newAccount, registerAccount } from '../fixtures/apps'
import {
  acceptGroup,
  befriend,
  closeDetails,
  createGroup,
  message,
  openChat,
  openDetails,
  openGroup,
  send,
} from '../fixtures/chat'

const PASSWORD = 'Deneme123*TwoServerGroupPassword'

// A group across two servers (docs/plans/pairwise-groups.md): it lives on
// its creator's server (its home); a member on another server reaches the
// home only through their own server's anonymous relay, and messages go to
// each member's own server, sealed. A removal made on the home reaches the
// remote member through the change notice, and the removed member's later
// messages are refused.
test.describe('groups across two servers', () => {
  test.skip(!hasSecondaryServer(), 'set E2E_SECONDARY_APP_ORIGIN for the isolated federation topology')

  test('a remote member joins, writes, learns of a removal and of a new name', async ({ browser }) => {
    test.slow()
    const tag = Date.now().toString(36)
    const alice = newAccount('fedgrpalice', PASSWORD, 'primary')
    const carol = newAccount('fedgrpcarol', PASSWORD, 'primary')
    const bob = newAccount('fedgrpbob', PASSWORD, 'secondary')
    const contextA = await browser.newContext()
    const contextB = await browser.newContext()
    const contextC = await browser.newContext()
    await registerAccount(contextA, alice)
    await registerAccount(contextB, bob)
    await registerAccount(contextC, carol)
    const pageA = await openChat(contextA, 'primary')
    const pageB = await openChat(contextB, 'secondary')
    const pageC = await openChat(contextC, 'primary')

    // Bob's browser talks only to his own server: the home is reached
    // through its relay.
    const home = new URL(apiUrl('/', 'primary')).host
    const toHome: string[] = []
    pageB.on('request', (request) => {
      if (new URL(request.url()).host === home) toHome.push(request.url())
    })

    await befriend(pageA, pageB, bob.address, alice.username)
    await befriend(pageA, pageC, carol.username, alice.username)
    const groupId = await createGroup(pageA, [bob.username, carol.username], `Across ${tag}`)
    await acceptGroup(pageB, groupId)
    await acceptGroup(pageC, groupId)

    const fromAlice = `fed-group-from-alice-${tag}`
    await openGroup(pageA, groupId)
    await send(pageA, fromAlice)
    await expect(message(pageB, fromAlice)).toBeVisible({ timeout: 60_000 })
    await expect(message(pageC, fromAlice)).toBeVisible({ timeout: 60_000 })
    const fromBob = `fed-group-from-bob-${tag}`
    await send(pageB, fromBob)
    await expect(message(pageA, fromBob)).toBeVisible({ timeout: 60_000 })
    await expect(message(pageC, fromBob)).toBeVisible({ timeout: 60_000 })

    // Alice removes Carol. Bob hears of it from Alice's change notice and
    // catches up; his next message doesn't go to Carol, and Carol's later
    // one isn't taken by him.
    await openDetails(pageA)
    await pageA
      .getByTestId('chat-group-members')
      .getByRole('button', { name: new RegExp(`^Remove ${carol.username}`) })
      .click()
    await expect(pageA.getByTestId('chat-group-members')).toContainText('2 members', { timeout: 60_000 })
    await closeDetails(pageA)
    const afterRemoval = `fed-group-after-removal-${tag}`
    await send(pageA, afterRemoval)
    await expect(message(pageB, afterRemoval)).toBeVisible({ timeout: 60_000 })
    const bobAfter = `fed-group-bob-after-removal-${tag}`
    await send(pageB, bobAfter)
    await expect(message(pageA, bobAfter)).toBeVisible({ timeout: 60_000 })
    const carolLate = `fed-group-carol-late-${tag}`
    await send(pageC, carolLate)
    await pageB.reload()
    await openGroup(pageB, groupId)
    await expect(message(pageB, bobAfter)).toBeVisible({ timeout: 90_000 })
    await expect(message(pageB, carolLate)).toHaveCount(0)
    await expect(message(pageC, bobAfter)).toHaveCount(0)

    // A new name reaches the remote member.
    await openDetails(pageA)
    await pageA.getByTestId('chat-group-rename').click()
    await pageA.getByTestId('chat-group-title-input').fill(`Renamed ${tag}`)
    await pageA.getByTestId('chat-group-title-save').click()
    await closeDetails(pageA)
    await expect(pageB.getByTestId(`chat-group-${groupId}`)).toContainText(`Renamed ${tag}`, { timeout: 90_000 })

    expect(toHome).toEqual([])
    await contextA.close()
    await contextB.close()
    await contextC.close()
  })
})
