import { execSync } from 'node:child_process'
import { expect, test, type BrowserContext, type Page } from '@playwright/test'
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

/** Ada renames; her Chat and Bob's follow; a conversation both ways first. */
async function renamedConversation(browser: import('@playwright/test').Browser, tag: number) {
  const ada = newAccount('adaold', PASSWORD)
  const bob = newAccount('bobrn', PASSWORD)
  const renamed = newAccount('adanew', PASSWORD).username
  const contextA = await browser.newContext()
  const contextB = await browser.newContext()
  await registerAccount(contextA, ada)
  await registerAccount(contextB, bob)
  const pageA = await openChat(contextA)
  const pageB = await openChat(contextB)
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
  await pageA.reload()
  await openConversationWith(pageA, bob.username)
  await expect(message(pageA, reply)).toBeVisible({ timeout: 60_000 })
  return { ada, bob, renamed, pageA, pageB, hello, reply }
}

/** What an administrator's "free now" does (`POST /api/admin/names/:name/free`). */
function freeName(psql: string, name: string): void {
  execSync(psql, {
    input: `UPDATE mail_addresses SET state = 'freed', receive_until = NULL
              WHERE user_id = (SELECT user_id FROM account_names WHERE folded = kutup_fold('${name}'))
                AND split_part(folded, '@', 1) = kutup_fold('${name}') AND state IN ('receiving', 'closed');
            DELETE FROM account_names WHERE folded = kutup_fold('${name}');`,
    stdio: ['pipe', 'ignore', 'inherit'],
  })
}

/** Opens the direct conversation with `address` by its link (names can be alike). */
async function openThread(page: Page, address: string): Promise<void> {
  await page.goto(appUrl('chat', `/c/${encodeURIComponent(`direct:${address}`)}`))
  // A message request has no composer yet: wait for Chat itself.
  await expect(page.getByRole('region', { name: 'Conversations' })).toBeVisible({ timeout: 60_000 })
}

function renameNotices(page: Page) {
  return page.getByTestId('chat-rename-notice')
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

  test('someone who takes a left name is someone new, never in the old thread', async ({ browser }) => {
    const psql = process.env.E2E_PSQL
    test.skip(!psql, 'E2E_PSQL: a command that runs SQL from its stdin against the test stack database')
    test.slow()
    const tag = Date.now()
    const { ada, bob, renamed, pageB, hello } = await renamedConversation(browser, tag)
    // Bob follows Ada first.
    await pageB.reload()
    await openConversationWith(pageB, ada.username)
    await send(pageB, `follow-${tag}`)
    await expect(renameNotices(pageB)).toHaveCount(1, { timeout: 60_000 })

    // Ada's old name is freed, and Mallory registers it.
    freeName(psql!, ada.username)
    const mallory = { ...newAccount('mallory', PASSWORD), username: ada.username, address: ada.address }
    const contextM = await browser.newContext()
    await registerAccount(contextM, mallory)
    const pageM = await openChat(contextM)
    const claim = `it-is-ada-${tag}`
    await openDirectChat(pageM, bob.username)
    await send(pageM, claim)

    // Bob gets a request from someone new at the old name; Ada's thread is untouched.
    await openThread(pageB, ada.address)
    await expect(message(pageB, claim)).toBeVisible({ timeout: 60_000 })
    await expect(pageB).toHaveURL(new RegExp(encodeURIComponent(`direct:${ada.address}`)))
    await openThread(pageB, `${renamed}@${ada.address.split('@')[1]}`)
    await expect(message(pageB, hello)).toBeVisible({ timeout: 60_000 })
    await expect(message(pageB, claim)).toHaveCount(0)
    await expect(renameNotices(pageB)).toHaveCount(1)
    await openThread(pageB, ada.address)
    await expect(message(pageB, hello)).toHaveCount(0)
    await expect(pageB.getByRole('button', { name: 'Accept', exact: true })).toBeVisible()
  })
})
