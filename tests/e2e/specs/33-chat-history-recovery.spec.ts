import { expect, test, type BrowserContext, type Page, type Request } from '@playwright/test'
import { recordSafeCheckpoint } from '../safe-diagnostics'

const PASSWORD = 'Deneme123*ContinuousBackupPassword'

async function captureMnemonic(page: Page): Promise<string> {
  const allText = await page.evaluate(() => document.body.innerText)
  const seen = new Map<number, string>()
  for (const match of allText.matchAll(/(?:^|\s)(\d{1,2})[.)]\s*([a-z]+)\b/gim)) {
    const index = Number(match[1])
    if (index >= 1 && index <= 24 && !seen.has(index)) seen.set(index, match[2])
  }
  const words = Array.from({ length: 24 }, (_, index) => seen.get(index + 1))
  if (words.some(word => !word)) throw new Error('failed to capture recovery mnemonic')
  return words.join(' ')
}

async function register(
  context: BrowserContext,
  email: string,
  username: string,
): Promise<string> {
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
  return mnemonic
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
  await expect(page.getByTestId('chat-device-status')).toHaveText(/Device \d+/, { timeout: 90_000 })
}

async function openNoteToSelf(page: Page): Promise<void> {
  await page.getByRole('complementary').getByText('Note to Self', { exact: true }).click()
}

async function backupCursor(page: Page): Promise<number> {
  await page.getByTestId('chat-devices-button').click()
  const status = page.getByTestId('chat-backup-state')
  await expect(status).toHaveAttribute('data-current-cursor', /^\d+$/, { timeout: 45_000 })
  const cursor = Number(await status.getAttribute('data-current-cursor'))
  await page.keyboard.press('Escape')
  return cursor
}

async function waitForProtection(page: Page, afterCursor: number): Promise<string> {
  await page.getByTestId('chat-devices-button').click()
  const status = page.getByTestId('chat-backup-state')
  await expect(status).toHaveText('Protected', { timeout: 45_000 })
  await expect.poll(async () => Number(await status.getAttribute('data-current-cursor')), {
    timeout: 45_000,
    intervals: [250, 500, 1_000, 2_000],
  }).toBeGreaterThan(afterCursor)
  const latest = page.getByTestId('chat-backup-latest-protected')
  await expect(latest).not.toContainText(/waiting/i, { timeout: 45_000 })
  const text = (await latest.textContent())?.trim() ?? ''
  expect(text).not.toBe('')
  await page.keyboard.press('Escape')
  return text
}

async function sendNoteAttachment(
  page: Page,
  filename: string,
  plaintext: string,
): Promise<void> {
  const protectedCopy = page.waitForResponse(response => {
    const path = new URL(response.url()).pathname
    return response.request().method() === 'POST'
      && path === '/api/chat/backup/media/copy'
      && response.ok()
  }, { timeout: 45_000 })
  await page.getByTestId('chat-attachment-input').setInputFiles({
    name: filename,
    mimeType: 'text/plain',
    buffer: Buffer.from(plaintext, 'utf8'),
  })
  await expect(page.getByText(filename, { exact: true })).toBeVisible({ timeout: 45_000 })
  await protectedCopy
}

function restorationSideEffect(request: Request): string | undefined {
  const path = new URL(request.url()).pathname
  if (path.includes('history-transfer')) return `${request.method()} ${path}`
  if (request.method() === 'POST'
      && (path.endsWith('/chat/messages/ack') || path.endsWith('/chat/mls/messages/ack'))) {
    return `${request.method()} ${path}`
  }
  return undefined
}

test('a clean browser automatically restores server-protected Chat history', async ({
  browser,
  baseURL,
}) => {
  test.slow()
  if (!baseURL) throw new Error('base URL is required')
  const run = `${Date.now().toString(36)}-${process.pid.toString(36)}`
  const username = `user-${run}`.slice(0, 32)
  const email = `user-${run}@kutup.dev`
  const sourceContext = await browser.newContext({ baseURL })
  recordSafeCheckpoint('single-history-recovery', 'source-context-created')

  // The phrase deliberately remains only in this Playwright process. The
  // clean-browser recovery path below signs in normally and copies no state.
  const recoveryPhrase = await register(sourceContext, email, username)
  expect(recoveryPhrase.split(' ')).toHaveLength(24)
  const source = await login(sourceContext, email)
  await openChat(source)
  await openNoteToSelf(source)

  const cursorBeforeMessage = await backupCursor(source)
  const message = `protected-before-browser-loss-${run}`
  const input = source.getByRole('main').getByRole('textbox')
  await input.fill(message)
  await input.press('Enter')
  await expect(source.getByRole('main').getByText(message, { exact: true })).toBeVisible()
  const protectedAt = await waitForProtection(source, cursorBeforeMessage)
  recordSafeCheckpoint('single-history-recovery', 'source-history-protected', { records: 1 })

  // Browser loss is genuine: close the only source context before creating a
  // new context with no cookies, sessions, Cache API, local storage, or IDB.
  await sourceContext.close()
  recordSafeCheckpoint('single-history-recovery', 'source-browser-lost', { records: 1 })
  const restoredContext = await browser.newContext({ baseURL })
  const forbiddenActivity: string[] = []
  restoredContext.on('request', request => {
    const activity = restorationSideEffect(request)
    if (activity) forbiddenActivity.push(activity)
  })

  const restored = await login(restoredContext, email)
  await openChat(restored)
  await openNoteToSelf(restored)
  await expect(restored.getByRole('main').getByText(message, { exact: true })).toBeVisible({
    timeout: 45_000,
  })
  recordSafeCheckpoint('single-history-recovery', 'clean-browser-restored', { records: 1 })
  expect(forbiddenActivity, 'restore must not acknowledge mailbox rows or use device transfer')
    .toEqual([])
  await expect(restored.getByText(/start from scratch/i)).toHaveCount(0)
  await expect(restored.getByText(/request history|approve history|restore history/i)).toHaveCount(0)

  const restoredCursor = await backupCursor(restored)
  expect(restoredCursor).toBeGreaterThanOrEqual(cursorBeforeMessage + 1)
  expect(protectedAt).not.toMatch(/waiting/i)

  await restored.reload()
  await expect(restored.getByRole('heading', { name: 'Messages' })).toBeVisible({ timeout: 90_000 })
  await openNoteToSelf(restored)
  await expect(restored.getByRole('main').getByText(message, { exact: true })).toBeVisible()

  await restored.getByTestId('chat-reply-button').click()
  await expect(restored.getByTestId('chat-reply-composer')).toContainText(message)
  const reply = `reply-to-restored-history-${run}`
  const replyInput = restored.getByRole('main').getByRole('textbox')
  await replyInput.fill(reply)
  await replyInput.press('Enter')
  await expect(restored.getByRole('main').getByText(reply, { exact: true })).toBeVisible()
  await expect(restored.getByTestId('chat-reply-context')).toContainText(message)
  await waitForProtection(restored, restoredCursor)

  await restored.reload()
  await expect(restored.getByRole('heading', { name: 'Messages' })).toBeVisible({ timeout: 90_000 })
  await openNoteToSelf(restored)
  await expect(restored.getByRole('main').getByText(reply, { exact: true })).toBeVisible()
  await expect(restored.getByTestId('chat-reply-context')).toContainText(message)
  await restoredContext.close()
  recordSafeCheckpoint('single-history-recovery', 'reload-and-reply-persisted', { records: 2 })
})

test('protected media restores lazily and presents an unavailable state without partial import', async ({
  browser,
  baseURL,
}) => {
  test.slow()
  if (!baseURL) throw new Error('base URL is required')
  const run = `${Date.now().toString(36)}-${process.pid.toString(36)}`
  const username = `media-${run}`.slice(0, 32)
  const email = `media-${run}@kutup.dev`
  const filename = `protected-media-${run}.txt`
  const sourceContext = await browser.newContext({ baseURL })
  recordSafeCheckpoint('single-media-recovery', 'source-context-created')
  await register(sourceContext, email, username)
  const source = await login(sourceContext, email)
  await openChat(source)
  await openNoteToSelf(source)
  const cursorBeforeMedia = await backupCursor(source)
  await sendNoteAttachment(source, filename, `protected media ${run}`)
  await waitForProtection(source, cursorBeforeMedia)
  recordSafeCheckpoint('single-media-recovery', 'source-media-protected', { media: 1 })
  await sourceContext.close()

  const restoredContext = await browser.newContext({ baseURL })
  const mediaGets: string[] = []
  restoredContext.on('request', request => {
    const path = new URL(request.url()).pathname
    if (request.method() === 'GET'
        && (path.includes('/chat/media/objects/') || path.includes('/chat/backup/media/'))) {
      mediaGets.push(path)
    }
  })
  // Simulate expiry of the ordinary 45-day delivery copy. The independent
  // protected-history copy must still be usable after clean-browser restore.
  await restoredContext.route('**/api/chat/media/objects/*', route => route.fulfill({ status: 404 }))
  const restored = await login(restoredContext, email)
  await openChat(restored)
  await openNoteToSelf(restored)
  await expect(restored.getByText(filename, { exact: true })).toBeVisible({ timeout: 45_000 })
  recordSafeCheckpoint('single-media-recovery', 'media-metadata-restored', { media: 1 })
  expect(mediaGets, 'restoring history must not eagerly download protected media').toEqual([])

  const protectedDownload = restored.waitForResponse(response => {
    const path = new URL(response.url()).pathname
    return response.request().method() === 'GET'
      && path.includes('/api/chat/backup/media/')
      && response.ok()
  })
  await restored.getByRole('button', { name: `Download ${filename} into Kutup` }).click()
  await protectedDownload
  await expect(restored.getByRole('button', { name: `${filename} is available in Kutup` }))
    .toBeVisible({ timeout: 45_000 })
  recordSafeCheckpoint('single-media-recovery', 'protected-media-downloaded', { media: 1 })
  expect(mediaGets.some(path => path.includes('/chat/media/objects/'))).toBe(true)
  expect(mediaGets.some(path => path.includes('/chat/backup/media/'))).toBe(true)

  await restored.getByRole('button', { name: `More actions for ${filename}` }).click()
  const clearLocalCopy = restored.getByRole('menuitem', { name: 'Clear local copy' })
  await expect(clearLocalCopy).toBeVisible()
  // Chat state polling can rerender the Radix menu between Playwright's
  // stability checks. Dispatch the already-visible production menu action
  // synchronously so this assertion tests behavior rather than animation.
  await clearLocalCopy.evaluate(element => (element as HTMLElement).click())
  await expect(restored.getByRole('button', { name: `Download ${filename} into Kutup` }))
    .toBeVisible({ timeout: 45_000 })
  await restoredContext.route(
    '**/api/chat/backup/media/*',
    route => route.fulfill({ status: 404 }),
  )
  await restored.getByRole('button', { name: `Download ${filename} into Kutup` }).click()
  await expect(restored.locator('[data-sonner-toast][data-type="error"]')).toContainText(
    'Encrypted attachment download failed',
    { timeout: 45_000 },
  )
  const attachmentMessage = restored.getByTestId('chat-message').filter({ hasText: filename })
  await expect(attachmentMessage.getByText(filename, { exact: true })).toBeVisible()
  await expect(attachmentMessage).toContainText('encrypted')
  await expect(restored.getByRole('button', { name: `Download ${filename} into Kutup` }))
    .toBeVisible()
  await restoredContext.close()
  recordSafeCheckpoint('single-media-recovery', 'unavailable-media-contained', { media: 1 })
})
