import { expect, test, type Page } from '@playwright/test'
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

const PASSWORD = 'Deneme123*GroupLinkPassword'

/** The members' panel of the group open on `page`, caught up by reopening it. */
async function reopenDetails(page: Page, groupId: string): Promise<void> {
  await closeDetails(page)
  await page.reload()
  await openGroup(page, groupId)
  await openDetails(page)
}

// A group's link (docs/plans/pairwise-groups.md §4, §11): an administrator
// turns it on with approval, a stranger asks through it, the administrator
// sees the request when their app next checks the group and approves it;
// then announcements-only, a ban that resets the link, and the lines each
// change leaves in the timeline.
test('a stranger asks through the group link, is approved, then banned; the old link stops working', async ({ browser }) => {
  test.slow()
  const tag = Date.now().toString(36)
  const alice = newAccount('lnkalice', PASSWORD)
  const bob = newAccount('lnkbob', PASSWORD)
  const carol = newAccount('lnkcarol', PASSWORD)
  const contextA = await browser.newContext()
  const contextB = await browser.newContext()
  const contextC = await browser.newContext()
  await registerAccount(contextA, alice)
  await registerAccount(contextB, bob)
  await registerAccount(contextC, carol)
  const pageA = await openChat(contextA)
  const pageB = await openChat(contextB)
  const pageC = await openChat(contextC)
  await befriend(pageA, pageB, bob.username, alice.username)

  const groupId = await createGroup(pageA, bob.username, `Linked ${tag}`)
  await acceptGroup(pageB, groupId)

  // Alice describes it and turns the link on, with approval.
  await openGroup(pageA, groupId)
  await openDetails(pageA)
  await pageA.getByTestId('chat-group-description-edit').click()
  await pageA.getByTestId('chat-group-description-input').fill(`About ${tag}`)
  await pageA.getByTestId('chat-group-description-save').click()
  await expect(pageA.getByTestId('chat-group-description')).toHaveText(`About ${tag}`, { timeout: 45_000 })
  await pageA.getByTestId('chat-group-link-mode').click()
  await pageA.getByTestId('chat-group-link-mode-approve').click()
  const url = (await pageA.getByTestId('chat-group-link-url').textContent({ timeout: 45_000 }))!.trim()
  expect(url).toMatch(/\/join#[A-Za-z0-9_-]+$/)

  // Carol, a stranger, sees what the members wrote, and asks.
  await pageC.goto(url)
  const join = pageC.getByTestId('chat-group-join-dialog')
  await expect(join.getByTestId('chat-group-join-preview')).toContainText(`Linked ${tag}`, { timeout: 60_000 })
  await expect(join).toContainText(`About ${tag}`)
  await expect(join).toContainText('2 members')
  await expect(join).toContainText('An administrator approves new members')
  await join.getByTestId('chat-group-join-submit').click()
  await expect(join).toBeHidden({ timeout: 60_000 })

  // Alice sees it when her app next checks the group; she approves.
  await reopenDetails(pageA, groupId)
  const requests = pageA.getByTestId('chat-group-requests')
  await expect(requests).toContainText('1 request to join', { timeout: 90_000 })
  await requests.getByTestId('chat-group-request-approve').click()
  await expect(pageA.getByTestId('chat-group-members')).toContainText('3 members', { timeout: 60_000 })
  await closeDetails(pageA)

  // Carol is in: messages reach her, and Bob's timeline says how she came.
  const hello = `link-hello-${tag}`
  await send(pageA, hello)
  await openGroup(pageC, groupId)
  await expect(message(pageC, hello)).toBeVisible({ timeout: 90_000 })
  await openGroup(pageB, groupId)
  await expect(message(pageB, hello)).toBeVisible({ timeout: 90_000 })
  await expect(pageB.getByText(/asked to join through the group link/)).toBeVisible({ timeout: 90_000 })
  await expect(pageB.getByText(/approved .* request to join/)).toBeVisible()

  // Announcements only: Carol's composer goes; Alice still sends.
  await openDetails(pageA)
  await pageA.getByTestId('chat-group-announcements').click()
  await closeDetails(pageA)
  const news = `link-news-${tag}`
  await send(pageA, news)
  await expect(message(pageC, news)).toBeVisible({ timeout: 90_000 })
  await expect(pageC.getByText('Only administrators can send messages in this group.')).toBeVisible({ timeout: 90_000 })
  await expect(composer(pageC)).toHaveCount(0)

  // Alice bans Carol, resetting the link (the default): Carol is told, and
  // the link she holds no longer leads anywhere.
  await openDetails(pageA)
  await pageA.getByTestId(/^chat-group-member-aci:/).filter({ hasText: carol.username.split('@')[0] }).getByTestId('chat-group-member-ban').click()
  await expect(pageA.getByTestId('chat-group-ban-reset')).toBeChecked()
  await pageA.getByTestId('chat-group-ban-confirm').click()
  await expect(pageA.getByTestId('chat-group-members')).toContainText('2 members', { timeout: 60_000 })
  await expect(pageA.getByTestId('chat-group-bans')).toContainText('1 ban')
  await expect(pageC.getByText("You're no longer a member of this group.")).toBeVisible({ timeout: 90_000 })
  await pageC.goto(url)
  await expect(pageC.getByTestId('chat-group-join-failed')).toContainText('no longer works', { timeout: 60_000 })

  await contextA.close()
  await contextB.close()
  await contextC.close()
})
