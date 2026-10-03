// Call links: a call anyone holding the link can join, with or without a
// Kutup account (docs/chat-calls.md). An account makes a link; a browser
// with no account opens it, chooses a name and joins; both see each other
// by the names they chose; deleting the link stops new joins. Needs an SFU
// (`docker compose --profile sfu`), so it skips on a stack without one.

import { expect, test, type Page } from '@playwright/test'
import { apiUrl, appUrl, newAccount, registerAccount } from '../fixtures/apps'
import { openChat } from '../fixtures/chat'

const PASSWORD = 'Deneme123*CallLinksPassword'

function tile(page: Page, name: string) {
  return page.locator(`[data-testid="chat-group-call-tile"][data-name="${name}"]`)
}

async function join(page: Page, name: string, video: boolean): Promise<void> {
  await expect(page.getByRole('heading', { name: 'Join the call' })).toBeVisible({ timeout: 60_000 })
  await page.getByTestId('chat-link-call-name').fill(name)
  await page.getByTestId(video ? 'chat-link-call-join-video' : 'chat-link-call-join').click()
  await expect(page.getByTestId('chat-link-call-screen')).toHaveAttribute('data-phase', 'active', { timeout: 60_000 })
}

test('someone without an account joins a call through a link', async ({ browser, request }) => {
  test.slow()
  const capabilities = (await (await request.get(apiUrl('/auth/settings'))).json()) as { chat: { callLinks?: boolean } }
  test.skip(!capabilities.chat.callLinks, 'this stack has no SFU (docker compose --profile sfu)')

  const owner = newAccount('linkowner', PASSWORD)
  const ownerContext = await browser.newContext()
  await registerAccount(ownerContext, owner)
  const chat = await openChat(ownerContext)

  // The owner makes a link. What reaches the server is the room, a public
  // nonce and the hash of the access token; never the link itself.
  await chat.getByRole('button', { name: 'New chat' }).first().click()
  await chat.getByTestId('chat-open-call-links').click()
  const dialog = chat.getByTestId('chat-call-links')
  await expect(dialog.getByTestId('chat-call-links-empty')).toBeVisible({ timeout: 30_000 })
  const registration = chat.waitForRequest((sent) => sent.method() === 'POST' && new URL(sent.url()).pathname === '/api/chat/call-links')
  await dialog.getByTestId('chat-call-link-create').click()
  const registered = (await registration).postDataJSON() as Record<string, string>
  expect(Object.keys(registered).sort()).toEqual(['accessTokenHash', 'nonce', 'roomId'])
  const url = await dialog.getByTestId('chat-call-link-url').inputValue()
  expect(url).toMatch(/\/call#[A-Za-z0-9_-]{44}$/)
  expect(JSON.stringify(registered)).not.toContain(url.split('#')[1])

  // Another of the owner's sessions derives the same link from the account.
  await chat.reload()
  await chat.getByRole('button', { name: 'New chat' }).first().click({ timeout: 120_000 })
  await chat.getByTestId('chat-open-call-links').click()
  await expect(chat.getByTestId('chat-call-link-url')).toHaveValue(url, { timeout: 30_000 })
  await chat.keyboard.press('Escape')

  // A browser with no account at all opens the link.
  const guestContext = await browser.newContext()
  const guest = await guestContext.newPage()
  const requests: string[] = []
  guest.on('request', (sent) => requests.push(sent.url()))
  await guest.goto(url)
  await join(guest, 'Guest Gül', true)
  // The fragment never left the browser, and no sign-in was asked for.
  expect(requests.some((sent) => sent.includes(url.split('#')[1]))).toBe(false)
  expect(requests.some((sent) => /\/login|\/api\/auth\/forks/.test(sent))).toBe(false)

  // The owner joins the same call from the link.
  const ownerCall = await ownerContext.newPage()
  await ownerCall.goto(url)
  await join(ownerCall, 'Owner Ada', false)

  // Each sees the other by the name they chose.
  await expect(tile(guest, 'Owner Ada')).toBeVisible({ timeout: 60_000 })
  await expect(tile(ownerCall, 'Guest Gül')).toBeVisible({ timeout: 60_000 })
  await expect(tile(ownerCall, 'Guest Gül')).toHaveAttribute('data-video', 'on', { timeout: 60_000 })
  await expect(guest.getByTestId('chat-call-brand')).toContainText('Kutup')
  await guest.getByTestId('chat-call-people-button').click()
  await expect(guest.getByTestId('chat-call-person')).toHaveCount(2)
  // A link call has no conversation behind it: no chat tab.
  await expect(guest.getByTestId('chat-call-tab-chat')).toHaveCount(0)
  await guest.getByTestId('chat-call-panel-close').click()

  // The guest shares a screen; the owner sees it.
  await guest.getByTestId('chat-link-call-screen-share').click()
  await expect(ownerCall.getByTestId('chat-group-call-screen-tile')).toBeVisible({ timeout: 60_000 })
  await expect
    .poll(() => ownerCall.getByTestId('chat-group-call-screen-tile').locator('video').evaluate((video) => (video as HTMLVideoElement).videoWidth), { timeout: 45_000 })
    .toBeGreaterThan(0)
  await guest.getByTestId('chat-link-call-screen-share').click()
  await expect(ownerCall.getByTestId('chat-group-call-screen-tile')).toHaveCount(0, { timeout: 45_000 })

  // Leaving returns to the join form, which can join again.
  await guest.getByTestId('chat-link-call-leave').click()
  await expect(guest.getByTestId('chat-link-call-left')).toBeVisible({ timeout: 30_000 })
  await expect(tile(ownerCall, 'Guest Gül')).toHaveCount(0, { timeout: 45_000 })

  // The owner deletes the link: nobody can join through it any more.
  await chat.getByRole('button', { name: 'New chat' }).first().click()
  await chat.getByTestId('chat-open-call-links').click()
  await chat.getByTestId('chat-call-link-delete').click()
  await chat.getByRole('alertdialog').getByRole('button', { name: 'Delete', exact: true }).click()
  await expect(chat.getByTestId('chat-call-links-empty')).toBeVisible({ timeout: 30_000 })
  await expect(guest.getByTestId('chat-link-call-name')).toHaveValue('Guest Gül')
  await guest.getByTestId('chat-link-call-join').click()
  await expect(guest.getByTestId('chat-link-call-failure')).toHaveAttribute('data-reason', 'gone', { timeout: 30_000 })

  await ownerCall.getByTestId('chat-link-call-leave').click()
  await guestContext.close()
  await ownerContext.close()
})

test('a changed or incomplete link is refused before anything is sent', async ({ browser }) => {
  const context = await browser.newContext()
  const page = await context.newPage()
  const api: string[] = []
  page.on('request', (sent) => {
    if (new URL(sent.url()).pathname.startsWith('/api/chat/')) api.push(sent.url())
  })
  await page.goto(appUrl('chat', '/call#not-a-link'))
  await expect(page.getByRole('heading', { name: 'This is not a call link' })).toBeVisible({ timeout: 60_000 })
  expect(api).toEqual([])
  await context.close()
})
