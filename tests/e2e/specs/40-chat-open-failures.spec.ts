// What Chat offers when it cannot open depends on why. A server that cannot
// be reached is waited out: Chat retries by itself and offers nothing
// destructive. "Repair this browser", which discards the browser's Chat
// device, is only for a failure of the browser's own state.

import { expect, test } from '@playwright/test'
import { newAccount, registerAccount } from '../fixtures/apps'
import { openChat, openChats } from '../fixtures/chat'

const PASSWORD = 'Deneme123*OpenFailurePassword'

test('an unreachable server is retried, with no repair offered', async ({ browser }) => {
  test.slow()
  const context = await browser.newContext()
  await registerAccount(context, newAccount('openfail', PASSWORD))
  const page = await openChat(context)
  const deviceBefore = await page.evaluate(() => Object.keys(localStorage).filter((key) => key.startsWith('kutup:chat:device-id')).map((key) => localStorage.getItem(key)))

  await page.route('**/api/chat/**', (route) => route.fulfill({ status: 502, body: '' }))
  await page.reload()
  await expect(page.getByText("The server can't be reached")).toBeVisible({ timeout: 90_000 })
  await expect(page.getByText('Retrying…').first()).toBeVisible()
  await expect(page.getByRole('button', { name: 'Repair this browser' })).toHaveCount(0)
  await expect(page.getByRole('button', { name: 'Try now' })).toBeVisible()

  // The server is back: Chat opens without anyone doing anything, as the
  // same device.
  await page.unroute('**/api/chat/**')
  await openChats(page)
  const deviceAfter = await page.evaluate(() => Object.keys(localStorage).filter((key) => key.startsWith('kutup:chat:device-id')).map((key) => localStorage.getItem(key)))
  expect(deviceAfter).toEqual(deviceBefore)
  expect(deviceAfter.length).toBe(1)

  await context.close()
})

test('a failure of this browser\'s own state offers the repair', async ({ browser }) => {
  test.slow()
  const context = await browser.newContext()
  await registerAccount(context, newAccount('openstate', PASSWORD))
  const page = await openChat(context)

  await page.route('**/api/chat/messages*', (route) => route.fulfill({ status: 404, body: '' }))
  await page.reload()
  await expect(page.getByText('Chat could not open')).toBeVisible({ timeout: 90_000 })
  await expect(page.getByRole('button', { name: 'Repair this browser' })).toBeVisible()

  await context.close()
})
