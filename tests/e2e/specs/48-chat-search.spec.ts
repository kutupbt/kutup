import { expect, test, type Page } from '@playwright/test'
import { newAccount, registerAccount } from '../fixtures/apps'
import {
  acceptGroup,
  acceptRequest,
  composer,
  createGroup,
  deleteForEveryone,
  editMessage,
  message,
  openChat,
  openChats,
  openConversationWith,
  openDirectChat,
  send,
} from '../fixtures/chat'

const PASSWORD = 'Deneme123*ChatSearchPassword'

/** Searches from the chat list and returns the message results. */
async function search(page: Page, query: string) {
  const input = page.getByTestId('chat-search-input')
  // Going back to the list clears the box when it lands: only when needed,
  // and before typing.
  if (!(await input.isVisible())) await openChats(page)
  await input.fill(query)
  await expect(input).toHaveValue(query)
  return page.getByTestId('chat-search-result')
}

async function expectNothing(page: Page, query: string) {
  await search(page, query)
  await expect(page.getByText(`Nothing on this device matches “${query}”.`)).toBeVisible({ timeout: 30_000 })
}

test('search finds messages through the encrypted index: Turkish folding, word starts, edits and deletions', async ({ browser }) => {
  test.slow()
  const tag = Date.now().toString(36)
  const alice = newAccount('searchalice', PASSWORD)
  const bob = newAccount('searchbob', PASSWORD)
  const contextA = await browser.newContext()
  const contextB = await browser.newContext()
  await registerAccount(contextA, alice)
  await registerAccount(contextB, bob)
  const pageA = await openChat(contextA)
  const pageB = await openChat(contextB)

  const meeting = `İstanbul'da toplantı yarın ${tag}`
  const books = `Kitaplar geldi ${tag}`
  const before = `eski metin ${tag}`
  const after = `yeni metin ${tag}`
  const gone = `silinecek mesaj ${tag}`
  await openDirectChat(pageA, bob.username)
  for (const text of [meeting, books, before, gone]) await send(pageA, text)
  await openConversationWith(pageB, alice.username)
  await acceptRequest(pageB)
  await expect(message(pageB, gone)).toBeVisible({ timeout: 45_000 })

  // The sender's own history (sent messages) is searched as well as the
  // recipient's (received ones), folded alike.
  for (const page of [pageA, pageB]) {
    for (const query of ['istanbul', 'ISTANBUL', 'ıstanbul', 'toplanti']) {
      const results = await search(page, `${query} ${tag}`)
      await expect(results).toHaveCount(1, { timeout: 30_000 })
      await expect(results.first()).toContainText(meeting)
    }
    await expect(await search(page, `kitap ${tag}`)).toHaveCount(1, { timeout: 30_000 })
    // The middle of a word is not the start of one.
    await expectNothing(page, `taplar ${tag}`)
  }

  // An edit is found by its new text, not its old; a deleted message not at all.
  await openConversationWith(pageA, bob.username)
  await editMessage(pageA, before, after)
  await deleteForEveryone(pageA, gone)
  const edited = await search(pageA, `yeni ${tag}`)
  await expect(edited).toHaveCount(1, { timeout: 30_000 })
  await expect(edited.first()).toContainText(after)
  await expectNothing(pageA, `eski ${tag}`)
  await expectNothing(pageA, `silinecek ${tag}`)

  // Group messages are indexed too, on both sides.
  const groupId = await createGroup(pageA, bob.username, `Arama ${tag}`)
  await acceptGroup(pageB, groupId)
  await expect(pageA.getByTestId('chat-group-delivery-readiness')).toHaveCount(0, { timeout: 90_000 })
  await expect(composer(pageA)).toBeVisible()
  const groupText = `Grup toplantısı Çarşamba ${tag}`
  await send(pageA, groupText)
  await expect(message(pageB, groupText)).toBeVisible({ timeout: 45_000 })
  for (const page of [pageA, pageB]) {
    const inGroup = await search(page, `carsamba ${tag}`)
    await expect(inGroup).toHaveCount(1, { timeout: 30_000 })
    await expect(inGroup.first()).toContainText(groupText)
  }

  // A result opens the conversation at the message.
  // (Wait for this query's result: the previous query's stays on screen
  // until the new answer arrives.)
  const results = await search(pageB, `kitap ${tag}`)
  await expect(results).toHaveCount(1, { timeout: 30_000 })
  await expect(results.first()).toContainText(books)
  await results.first().click()
  await expect(message(pageB, books)).toBeVisible({ timeout: 30_000 })

  // The index is stored, encrypted, with the history: it answers after a reload.
  await pageB.reload()
  const afterReload = await search(pageB, `yarin ${tag}`)
  await expect(afterReload).toHaveCount(1, { timeout: 60_000 })
  await expect(afterReload.first()).toContainText(meeting)

  await contextA.close()
  await contextB.close()
})
