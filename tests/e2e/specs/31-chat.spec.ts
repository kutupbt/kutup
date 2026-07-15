import { expect, test, type BrowserContext, type Page } from '@playwright/test'

const PASSWORD = 'Deneme123*MyTestPasswordIsLong'

async function captureMnemonic(page: Page): Promise<string> {
  const allText = await page.evaluate(() => document.body.innerText)
  const seen = new Map<number, string>()
  for (const match of allText.matchAll(/(?:^|\s)(\d{1,2})[.)]\s*([a-z]+)\b/gim)) {
    const index = Number(match[1])
    if (index >= 1 && index <= 24 && !seen.has(index)) seen.set(index, match[2])
  }
  const words = Array.from({ length: 24 }, (_, index) => seen.get(index + 1))
  if (words.some((word) => !word)) {
    throw new Error(`failed to capture mnemonic; got: ${words.join(' ')}`)
  }
  return words.join(' ')
}

async function registerUser(
  context: BrowserContext,
  email: string,
  username: string,
): Promise<void> {
  const page = await context.newPage()
  await page.goto('/register')
  await page.locator('input[type=email]').fill(email)
  await page.getByLabel(/username/i).fill(username)
  const passwords = page.locator('input[type=password]')
  await passwords.nth(0).fill(PASSWORD)
  await passwords.nth(1).fill(PASSWORD)
  await page.locator('button[type=submit]').click()
  await expect(page.getByText(/once/i).first()).toBeVisible({ timeout: 30_000 })
  const mnemonic = await captureMnemonic(page)
  await page.getByRole('button', { name: /saved/i }).click()
  await page.locator('textarea').fill(mnemonic)
  await page.locator('button[type=submit]').click()
  await expect(page.getByRole('button', { name: /sign ?in/i })).toBeVisible({ timeout: 30_000 })
  await page.close()
}

async function login(
  context: BrowserContext,
  email: string,
  password: string,
): Promise<Page> {
  const page = await context.newPage()
  await page.goto('/login')
  await page.locator('input[type=email]').fill(email)
  await page.locator('input[type=password]').fill(password)
  await page.locator('button[type=submit]').click()
  await page.waitForURL(/drive/, { timeout: 30_000 })
  return page
}

async function openChat(page: Page): Promise<void> {
  await page.goto('/chat')
  await expect(page.getByRole('heading', { name: 'Messages' })).toBeVisible({ timeout: 60_000 })
  await expect(page.getByText(/End-to-end encrypted · device \d+/)).toBeVisible({
    timeout: 60_000,
  })
}

async function startConversation(page: Page, username: string): Promise<void> {
  await page.getByPlaceholder('Username').fill(username)
  await page.getByRole('button', { name: 'Start chat' }).click()
}

async function send(page: Page, text: string): Promise<void> {
  const composer = page.locator('main form input')
  await composer.fill(text)
  await page.getByRole('button', { name: 'Send' }).click()
}

function messageBubble(page: Page, text: string) {
  return page.getByRole('main').getByText(text, { exact: true })
}

test.describe('Signal-backed chat', () => {
  test('two accounts exchange encrypted messages and retain local history', async ({ browser }) => {
    test.slow()
    const contextA = await browser.newContext({ ignoreHTTPSErrors: true })
    const contextB = await browser.newContext({ ignoreHTTPSErrors: true })

    const tag = Date.now()
    const usernameA = `chatalice${tag % 1_000_000}`
    const emailA = `${usernameA}@kutup.local`
    const usernameB = `chatbob${tag % 1_000_000}`
    const emailB = `${usernameB}@kutup.local`
    await registerUser(contextA, emailA, usernameA)
    await registerUser(contextB, emailB, usernameB)
    const pageA = await login(contextA, emailA, PASSWORD)
    const pageB = await login(contextB, emailB, PASSWORD)

    // Opening registers each install, publishes its signed device manifest,
    // performs mailbox reconciliation, and starts the WebSocket hint channel.
    await openChat(pageA)
    await openChat(pageB)

    const fromA = `from-a-${tag}`
    await startConversation(pageA, usernameB)
    await send(pageA, fromA)
    await expect(messageBubble(pageB, fromA)).toBeVisible({ timeout: 30_000 })

    const fromB = `from-b-${tag}`
    await send(pageB, fromB)
    await expect(messageBubble(pageA, fromB)).toBeVisible({ timeout: 30_000 })

    // IndexedDB is the durable source of truth; a reload must not depend on
    // redelivery from the already-acked server mailbox.
    await pageA.reload()
    await expect(messageBubble(pageA, fromA)).toBeVisible({ timeout: 60_000 })
    await expect(messageBubble(pageA, fromB)).toBeVisible({ timeout: 60_000 })

    await contextA.close()
    await contextB.close()
  })
})
