import { expect, test, type Browser, type BrowserContext, type Page } from '@playwright/test'

const PASSWORD = 'Deneme123*HistoryRecoveryPassword'

async function captureMnemonic(page: Page): Promise<string> {
  const allText = await page.evaluate(() => document.body.innerText)
  const seen = new Map<number, string>()
  for (const match of allText.matchAll(/(?:^|\s)(\d{1,2})[.)]\s*([a-z]+)\b/gim)) {
    const index = Number(match[1])
    if (index >= 1 && index <= 24 && !seen.has(index)) seen.set(index, match[2])
  }
  const words = Array.from({ length: 24 }, (_, index) => seen.get(index + 1))
  if (words.some((word) => !word)) throw new Error('failed to capture recovery mnemonic')
  return words.join(' ')
}

async function register(context: BrowserContext, email: string, username: string): Promise<void> {
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

async function login(context: BrowserContext, email: string): Promise<Page> {
  const page = await context.newPage()
  await page.goto('/login')
  await page.locator('input[type=email]').fill(email)
  await page.locator('input[type=password]').fill(PASSWORD)
  await page.locator('button[type=submit]').click()
  await page.waitForURL(/\/drive/, { timeout: 30_000 })
  return page
}

async function openChat(page: Page): Promise<void> {
  await page.goto('/chat')
  await expect(page.getByRole('heading', { name: 'Messages' })).toBeVisible({ timeout: 90_000 })
  await expect(page.getByTestId('chat-device-status')).toHaveText(/Device \d+/, {
    timeout: 90_000,
  })
}

async function cloneAuthenticatedInstall(
  browser: Browser,
  sourceContext: BrowserContext,
  sourcePage: Page,
): Promise<{ context: BrowserContext; page: Page }> {
  const session = await sourcePage.evaluate(() => sessionStorage.getItem('kutup_session'))
  if (!session) throw new Error('source install has no authenticated session')
  const context = await browser.newContext({
    baseURL: new URL(sourcePage.url()).origin,
    storageState: await sourceContext.storageState(),
  })
  await context.addInitScript((savedSession) => {
    sessionStorage.setItem('kutup_session', savedSession)
  }, session)
  return { context, page: await context.newPage() }
}

test('a new browser restores signed end-to-end encrypted Chat history after approval', async ({
  browser,
  baseURL,
}) => {
  test.slow()
  if (!baseURL) throw new Error('base URL is required')
  const sourceContext = await browser.newContext({ baseURL })
  const tag = Date.now() % 1_000_000
  const username = `history${tag}`
  const email = `${username}@example.test`

  await register(sourceContext, email, username)
  const source = await login(sourceContext, email)
  await openChat(source)
  await source.getByRole('complementary').getByText('Note to Self', { exact: true }).click()
  const message = `history-before-new-device-${tag}`
  const input = source.getByRole('main').getByRole('textbox')
  await input.fill(message)
  await expect(source.getByRole('button', { name: 'Send', exact: true })).toBeEnabled()
  await input.press('Enter')
  await expect(source.getByText(message, { exact: true })).toBeVisible()

  const { context: targetContext, page: target } = await cloneAuthenticatedInstall(
    browser,
    sourceContext,
    source,
  )
  await openChat(target)
  await target.getByRole('complementary').getByText('Note to Self', { exact: true }).click()
  await expect(target.getByText(message, { exact: true })).toHaveCount(0)

  await target.getByTestId('chat-devices-button').click()
  await target.getByTestId('chat-history-request').click()
  await expect(target.getByText(/History requested/)).toBeVisible()

  await source.getByTestId('chat-devices-button').click()
  const sourceRecovery = source.getByTestId('chat-history-recovery')
  await expect(sourceRecovery.getByRole('button', { name: 'Approve' })).toBeVisible({
    timeout: 15_000,
  })
  await sourceRecovery.getByRole('button', { name: 'Approve' }).click()
  await expect(source.getByText(/Encrypted history prepared/)).toBeVisible({ timeout: 45_000 })

  const targetRecovery = target.getByTestId('chat-history-recovery')
  await expect(targetRecovery.getByRole('button', { name: 'Restore' })).toBeVisible({
    timeout: 15_000,
  })
  await targetRecovery.getByRole('button', { name: 'Restore' }).click()
  await expect(target.getByRole('heading', { name: 'Messages' })).toBeVisible({ timeout: 90_000 })
  await target.getByRole('complementary').getByText('Note to Self', { exact: true }).click()
  await expect(target.getByRole('main').getByText(message, { exact: true })).toBeVisible({
    timeout: 45_000,
  })

  await target.reload()
  await expect(target.getByRole('heading', { name: 'Messages' })).toBeVisible({ timeout: 90_000 })
  await target.getByRole('complementary').getByText('Note to Self', { exact: true }).click()
  await expect(target.getByRole('main').getByText(message, { exact: true })).toBeVisible()

  await target.getByTestId('chat-reply-button').click()
  await expect(target.getByTestId('chat-reply-composer')).toContainText(message)
  const reply = `reply-to-recovered-history-${tag}`
  const replyInput = target.getByRole('main').getByRole('textbox')
  await replyInput.fill(reply)
  await replyInput.press('Enter')
  await expect(target.getByRole('main').getByText(reply, { exact: true })).toBeVisible()
  await expect(target.getByTestId('chat-reply-context')).toContainText(message)

  await target.reload()
  await expect(target.getByRole('heading', { name: 'Messages' })).toBeVisible({ timeout: 90_000 })
  await target.getByRole('complementary').getByText('Note to Self', { exact: true }).click()
  await expect(target.getByRole('main').getByText(reply, { exact: true })).toBeVisible()
  await expect(target.getByTestId('chat-reply-context')).toContainText(message)

  await targetContext.close()
  await sourceContext.close()
})
