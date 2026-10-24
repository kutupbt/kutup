import { expect, test, type Page } from '@playwright/test'
import { newAccount, registerAccount } from '../fixtures/apps'
import {
  acceptGroup,
  befriend,
  createGroup,
  message,
  openChat,
  openGroup,
  send,
} from '../fixtures/chat'

const PASSWORD = 'Deneme123*GroupSendPassword'
const MULTI = /\/api\/chat\/anonymous\/messages\/multi(\?|$)/

/** The multi-recipient sends `page` makes from now on, with their answers. */
function watchMulti(page: Page): number[] {
  const statuses: number[] = []
  page.on('response', response => {
    const url = new URL(response.url())
    if (response.request().method() === 'POST' && MULTI.test(url.pathname + url.search)) {
      statuses.push(response.status())
    }
  })
  return statuses
}

// Group send endorsements (docs/plans/group-send-endorsements.md): each
// member's own server endorses it daily, the member shares that with the
// group's home, and a sender combines the members' endorsements into one
// token, so a message to the members of one server goes once, on the
// multi-recipient route. A member shares its endorsement when it sends; a
// device reads the others' when one lacks one (at most once a minute, and
// at once on a fresh page).
test('a group message goes once to every member of the server, with a token', async ({ browser }) => {
  test.slow()
  const tag = Date.now().toString(36)
  const alice = newAccount('gsealice', PASSWORD)
  const bob = newAccount('gsebob', PASSWORD)
  const carol = newAccount('gsecarol', PASSWORD)
  const contextA = await browser.newContext()
  const contextB = await browser.newContext()
  const contextC = await browser.newContext()
  await registerAccount(contextA, alice)
  await registerAccount(contextB, bob)
  await registerAccount(contextC, carol)
  let pageA = await openChat(contextA)
  const pageB = await openChat(contextB)
  const pageC = await openChat(contextC)
  await befriend(pageA, pageB, bob.username, alice.username)
  await befriend(pageA, pageC, carol.username, alice.username)

  const groupId = await createGroup(pageA, [bob.username, carol.username], `Endorsed ${tag}`)
  await acceptGroup(pageB, groupId)
  await acceptGroup(pageC, groupId)

  // Each member sends once, sharing its endorsement with the group's home.
  const pages = [pageA, pageB, pageC]
  for (const [index, page] of pages.entries()) {
    const text = `gse-hello-${index}-${tag}`
    await openGroup(page, groupId)
    await send(page, text)
    for (const other of pages) {
      await expect(message(other, text)).toBeVisible({ timeout: 60_000 })
    }
  }

  // A fresh page reads the others' endorsements before its first send:
  // that message goes to Bob and Carol in one multi-recipient request.
  await pageA.close()
  pageA = await openChat(contextA)
  const multi = watchMulti(pageA)
  await openGroup(pageA, groupId)
  const once = `gse-once-for-all-${tag}`
  await send(pageA, once)
  await expect(message(pageB, once)).toBeVisible({ timeout: 60_000 })
  await expect(message(pageC, once)).toBeVisible({ timeout: 60_000 })
  expect(multi).toEqual([200])

  await contextA.close()
  await contextB.close()
  await contextC.close()
})
