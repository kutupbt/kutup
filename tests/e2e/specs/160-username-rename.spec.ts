import { expect, test, type BrowserContext } from '@playwright/test'
import { appUrl, newAccount, registerAccount } from '../fixtures/apps'
import { acceptRequest, message, openChat, openConversationWith, openDirectChat, send } from '../fixtures/chat'

// A username rename (docs/plans/username-renames.md), end to end: Ada
// renames herself in Account; her Chat follows on its next start; Bob's Chat
// follows her verified rename chain when it next reaches for her old name,
// moves the thread with its line, and the conversation carries on.

const PASSWORD = 'Deneme123*MyTestPasswordIsLong'

async function rename(context: BrowserContext, to: string): Promise<void> {
  const page = await context.newPage()
  await page.goto(appUrl('account', '/settings/account'))
  await page.getByRole('button', { name: 'Change username' }).click()
  const dialog = page.getByRole('dialog')
  await dialog.getByLabel(/New username/).fill(to)
  await expect(dialog.getByRole('status')).toContainText('Available.', { timeout: 15_000 })
  await expect(dialog.getByText(/will receive mail for \d+ days and cannot send/)).toBeVisible()
  await dialog.getByLabel(/Current password/).fill(PASSWORD)
  await dialog.getByRole('button', { name: 'Change username' }).click()
  await expect(page.getByText(`Your username is now ${to}.`)).toBeVisible({ timeout: 60_000 })
  await expect(page.getByRole('dialog')).toBeHidden()
  // The old name is held, receiving mail for a while.
  await expect(page.getByRole('list', { name: 'Earlier names' })).toBeVisible()
  await page.close()
}

test.describe('username renames', () => {
  test('a conversation follows a renamed peer, with its line, both ways', async ({ browser }) => {
    test.slow()
    const tag = Date.now()
    const ada = newAccount('adaold', PASSWORD)
    const bob = newAccount('bobrn', PASSWORD)
    const renamed = newAccount('adanew', PASSWORD).username
    const contextA = await browser.newContext()
    const contextB = await browser.newContext()
    await registerAccount(contextA, ada)
    await registerAccount(contextB, bob)
    const pageA = await openChat(contextA)
    const pageB = await openChat(contextB)

    // A conversation both ways before the rename.
    const hello = `hello-${tag}`
    await openDirectChat(pageA, bob.username)
    await send(pageA, hello)
    await openConversationWith(pageB, ada.username)
    await expect(message(pageB, hello)).toBeVisible({ timeout: 60_000 })
    await acceptRequest(pageB)
    const reply = `reply-${tag}`
    await send(pageB, reply)
    await openConversationWith(pageA, bob.username)
    await expect(message(pageA, reply)).toBeVisible({ timeout: 60_000 })

    await rename(contextA, renamed)

    // Ada's Chat opens under her new name and publishes there.
    await pageA.reload()
    await openConversationWith(pageA, bob.username)
    await expect(message(pageA, reply)).toBeVisible({ timeout: 60_000 })

    // Bob writes to her as he knew her: his Chat follows her chain, and the
    // thread is hers under the new name, with the line.
    await pageB.reload()
    await openConversationWith(pageB, ada.username)
    const after = `after-rename-${tag}`
    await send(pageB, after)
    await expect(pageB.getByTestId('chat-rename-notice')).toHaveText(
      `${ada.username} changed their username to ${renamed}`,
      { timeout: 60_000 },
    )
    await expect(pageB).toHaveURL(new RegExp(encodeURIComponent(`direct:${renamed}@`)), { timeout: 30_000 })
    await expect(message(pageB, hello)).toBeVisible()
    await expect(message(pageB, after)).toBeVisible()

    // It reaches Ada, and her answer reaches Bob in the same thread.
    await openConversationWith(pageA, bob.username)
    await expect(message(pageA, after)).toBeVisible({ timeout: 60_000 })
    const answer = `answer-${tag}`
    await send(pageA, answer)
    await expect(message(pageB, answer)).toBeVisible({ timeout: 60_000 })
    await expect(pageB.getByTestId('chat-rename-notice')).toHaveCount(1)
  })
})
