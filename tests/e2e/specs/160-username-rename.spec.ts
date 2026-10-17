import { expect, test, type Browser, type BrowserContext, type Page } from '@playwright/test'
import { accountKey, apiUrl, appUrl, newAccount, registerAccount, signInAsAdmin } from '../fixtures/apps'
import { acceptRequest, message, openChat, openConversationWith, openDirectChat, send } from '../fixtures/chat'

// A username rename under account ids (docs/plans/account-ids.md): a thread
// is the account's, so Ada's rename keeps it; Bob's Chat follows her own
// signed rename chain and says so once, in the same thread. Someone who
// later takes her old name is another account: told as someone else, and a
// thread of their own.

const PASSWORD = 'Deneme123*MyTestPasswordIsLong'

async function rename(context: BrowserContext, to: string): Promise<void> {
  const page = await context.newPage()
  await page.goto(appUrl('account', '/settings/account'))
  await page.getByRole('button', { name: 'Change username' }).click()
  const dialog = page.getByRole('dialog')
  await dialog.getByLabel(/New username/).fill(to)
  await expect(dialog.getByRole('status')).toContainText('Available.', { timeout: 15_000 })
  await dialog.getByLabel(/Current password/).fill(PASSWORD)
  await dialog.getByRole('button', { name: 'Change username' }).click()
  await expect(page.getByText(`Your username is now ${to}.`)).toBeVisible({ timeout: 60_000 })
  await expect(page.getByRole('dialog')).toBeHidden()
  await page.close()
}

/** An administrator frees a held name at once (`POST /api/admin/names/:name/free`). */
async function freeName(browser: Browser, name: string): Promise<void> {
  const admin = await browser.newContext()
  await signInAsAdmin(admin)
  const page = await admin.newPage()
  const authorized = page.waitForRequest((request) => request.url().includes('/api/') && Boolean(request.headers()['authorization']))
  await page.goto(appUrl('account', '/admin/users'))
  const authorization = (await authorized).headers()['authorization']
  const status = await page.evaluate(
    async ({ url, authorization }) => (await fetch(url, { method: 'POST', headers: { Authorization: authorization } })).status,
    { url: apiUrl(`/admin/names/${encodeURIComponent(name)}/free`), authorization },
  )
  expect(status).toBe(204)
  await admin.close()
}

function renameNotices(page: Page) {
  return page.getByTestId('chat-rename-notice')
}

/** Opens the direct conversation with the account `key` by its link. */
async function openThread(page: Page, key: string): Promise<void> {
  await page.goto(appUrl('chat', `/c/${encodeURIComponent(`direct:${key}`)}`))
  await expect(page.getByRole('region', { name: 'Conversations' })).toBeVisible({ timeout: 60_000 })
}

test.describe('username renames', () => {
  test('a rename keeps the thread, told once; whoever takes the old name is someone new', async ({ browser }) => {
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
    // Ada's account, for good (her old address later belongs to someone else).
    const adaKey = accountKey(ada)
    const bobKey = accountKey(bob)

    // A conversation both ways before the rename.
    const hello = `hello-${tag}`
    await openDirectChat(pageA, bob.username)
    await send(pageA, hello)
    await openConversationWith(pageB, ada.username)
    await expect(message(pageB, hello)).toBeVisible({ timeout: 60_000 })
    await acceptRequest(pageB)
    const reply = `reply-${tag}`
    await send(pageB, reply)
    await expect(message(pageA, reply)).toBeVisible({ timeout: 60_000 })

    await rename(contextA, renamed)
    const server = ada.address.split('@')[1]

    // Bob's Chat follows Ada's chain: the line, once, in the same thread.
    await pageB.reload()
    await openThread(pageB, adaKey)
    await expect(renameNotices(pageB)).toHaveText(`${ada.username}@${server} changed their username to ${renamed}@${server}.`, {
      timeout: 60_000,
    })
    await expect(message(pageB, hello)).toBeVisible()
    await expect(message(pageB, reply)).toBeVisible()

    // The conversation carries on both ways, in the same thread.
    const after = `after-rename-${tag}`
    await send(pageB, after)
    await pageA.reload()
    await openThread(pageA, bobKey)
    await expect(message(pageA, after)).toBeVisible({ timeout: 60_000 })
    const answer = `answer-${tag}`
    await send(pageA, answer)
    await expect(message(pageB, answer)).toBeVisible({ timeout: 60_000 })
    await pageB.reload()
    await openThread(pageB, adaKey)
    await expect(message(pageB, answer)).toBeVisible({ timeout: 60_000 })
    await expect(renameNotices(pageB)).toHaveCount(1)

    // Ada's old name is freed, and Mallory takes it.
    await freeName(browser, ada.username)
    const mallory = { ...newAccount('mallory', PASSWORD), username: ada.username, address: ada.address }
    const contextM = await browser.newContext()
    await registerAccount(contextM, mallory)

    // Bob asks for the old address: someone else, told before anything opens.
    await pageB.getByRole('button', { name: 'New chat' }).first().click()
    const dialog = pageB.getByRole('dialog')
    await dialog.getByRole('combobox').fill(ada.address)
    await dialog.getByRole('combobox').press('Enter')
    await expect(dialog.getByTestId('chat-someone-else')).toContainText(`now ${renamed}@${server}`, { timeout: 60_000 })
    await dialog.getByRole('button', { name: 'Open anyway' }).click()
    await expect(dialog).toBeHidden()
    await expect(pageB).toHaveURL(new RegExp(encodeURIComponent(`direct:${accountKey(mallory)}`)), { timeout: 30_000 })

    // Mallory's thread is a new one; Ada's is untouched, with its one line.
    await expect(message(pageB, hello)).toHaveCount(0)
    await expect(renameNotices(pageB)).toHaveCount(0)
    await openThread(pageB, adaKey)
    await expect(message(pageB, hello)).toBeVisible({ timeout: 60_000 })
    await expect(renameNotices(pageB)).toHaveCount(1)

    await contextA.close()
    await contextB.close()
    await contextM.close()
  })
})
