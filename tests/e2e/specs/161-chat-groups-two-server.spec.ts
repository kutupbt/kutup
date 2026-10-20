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
  openConversationWith,
  openGroup,
  removeGroupMember,
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
    // catches up; his next message doesn't go to Carol, who is told of her
    // removal pairwise and can't send there any more.
    await openDetails(pageA)
    await removeGroupMember(pageA, carol.username)
    await expect(pageA.getByTestId('chat-group-members')).toContainText('2 members', { timeout: 60_000 })
    await closeDetails(pageA)
    const afterRemoval = `fed-group-after-removal-${tag}`
    await send(pageA, afterRemoval)
    await expect(message(pageB, afterRemoval)).toBeVisible({ timeout: 60_000 })
    const bobAfter = `fed-group-bob-after-removal-${tag}`
    await send(pageB, bobAfter)
    await expect(message(pageA, bobAfter)).toBeVisible({ timeout: 60_000 })
    await openGroup(pageC, groupId)
    await expect(pageC.getByText("You're no longer a member of this group.")).toBeVisible({ timeout: 90_000 })
    await pageB.reload()
    await openGroup(pageB, groupId)
    await expect(message(pageB, bobAfter)).toBeVisible({ timeout: 90_000 })
    // Absence is checked only once something sent later has arrived: a
    // direct message from Alice, sent after both, reaches each of them first.
    const probeB = `fed-group-probe-bob-${tag}`
    const probeC = `fed-group-probe-carol-${tag}`
    await openConversationWith(pageA, bob.username)
    await send(pageA, probeB)
    await openConversationWith(pageA, carol.username)
    await send(pageA, probeC)
    await openConversationWith(pageB, alice.username)
    await expect(message(pageB, probeB)).toBeVisible({ timeout: 90_000 })
    await openConversationWith(pageC, alice.username)
    await expect(message(pageC, probeC)).toBeVisible({ timeout: 90_000 })
    await openGroup(pageC, groupId)
    await expect(message(pageC, bobAfter)).toHaveCount(0)
    await openGroup(pageA, groupId)

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

  test('a stranger on another server joins through the group link, by their own server', async ({ browser }) => {
    test.slow()
    const tag = Date.now().toString(36)
    const alice = newAccount('fedlnkalice', PASSWORD, 'primary')
    const dave = newAccount('fedlnkdave', PASSWORD, 'secondary')
    const contextA = await browser.newContext()
    const contextD = await browser.newContext()
    await registerAccount(contextA, alice)
    await registerAccount(contextD, dave)
    const pageA = await openChat(contextA, 'primary')
    const pageD = await openChat(contextD, 'secondary')
    const home = new URL(apiUrl('/', 'primary')).host
    const toHome: string[] = []
    pageD.on('request', (request) => {
      if (new URL(request.url()).host === home) toHome.push(request.url())
    })

    const groupId = await createGroup(pageA, [], `Open ${tag}`)
    await openDetails(pageA)
    await pageA.getByTestId('chat-group-link-mode').click()
    await pageA.getByTestId('chat-group-link-mode-join').click()
    const url = (await pageA.getByTestId('chat-group-link-url').textContent({ timeout: 45_000 }))!.trim()
    await closeDetails(pageA)

    // Dave opens it in his own server's Chat: the fragment carries the
    // home, and his server relays.
    await pageD.goto(`${new URL(pageD.url()).origin}/join${new URL(url).hash}`)
    const join = pageD.getByTestId('chat-group-join-dialog')
    await expect(join.getByTestId('chat-group-join-preview')).toContainText(`Open ${tag}`, { timeout: 60_000 })
    await join.getByTestId('chat-group-join-submit').click()
    await pageD.waitForURL((at) => decodeURIComponent(at.pathname).includes(`/c/group:${groupId}`), { timeout: 90_000 })

    const hello = `fed-link-hello-${tag}`
    await openGroup(pageA, groupId)
    await send(pageA, hello)
    await expect(message(pageD, hello)).toBeVisible({ timeout: 90_000 })
    const back = `fed-link-back-${tag}`
    await send(pageD, back)
    await expect(message(pageA, back)).toBeVisible({ timeout: 90_000 })
    await expect(pageA.getByText(/joined the group through the group link/)).toBeVisible({ timeout: 90_000 })

    expect(toHome).toEqual([])
    await contextA.close()
    await contextD.close()
  })
})
