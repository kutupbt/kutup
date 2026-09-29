import { expect, test, type Page, type Request } from '@playwright/test'
import { newAccount, registerAccount, signIn } from '../fixtures/apps'
import { backupCursor, bubble, openChat, openNoteToSelf, send, waitForProtection } from '../fixtures/chat'
import { recordSafeCheckpoint } from '../safe-diagnostics'

const PASSWORD = 'Deneme123*ContinuousBackupPassword'

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
  await expect(bubble(page, filename).getByText(filename, { exact: true })).toBeVisible({ timeout: 45_000 })
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

test('a clean browser automatically restores server-protected Chat history', async ({ browser }) => {
  test.slow()
  const run = `${Date.now().toString(36)}-${process.pid.toString(36)}`
  const account = newAccount('user', PASSWORD)
  const sourceContext = await browser.newContext()
  recordSafeCheckpoint('single-history-recovery', 'source-context-created')

  // The phrase deliberately remains only in this Playwright process. The
  // clean-browser recovery path below signs in normally and copies no state.
  const recoveryPhrase = await registerAccount(sourceContext, account)
  expect(recoveryPhrase.split(' ')).toHaveLength(24)
  const source = await openChat(sourceContext)
  await openNoteToSelf(source)

  const cursorBeforeMessage = await backupCursor(source)
  const message = `protected-before-browser-loss-${run}`
  await send(source, message)
  await expect(bubble(source, message)).toBeVisible()
  const protectedAt = await waitForProtection(source, cursorBeforeMessage)
  recordSafeCheckpoint('single-history-recovery', 'source-history-protected', { records: 1 })

  // Browser loss is genuine: close the only source context before creating a
  // new context with no cookies, sessions, Cache API, local storage, or IDB.
  await sourceContext.close()
  recordSafeCheckpoint('single-history-recovery', 'source-browser-lost', { records: 1 })
  const restoredContext = await browser.newContext()
  const forbiddenActivity: string[] = []
  restoredContext.on('request', request => {
    const activity = restorationSideEffect(request)
    if (activity) forbiddenActivity.push(activity)
  })

  await signIn(restoredContext, account)
  const restored = await openChat(restoredContext)
  await openNoteToSelf(restored)
  await expect(bubble(restored, message)).toBeVisible({ timeout: 45_000 })
  recordSafeCheckpoint('single-history-recovery', 'clean-browser-restored', { records: 1 })
  expect(forbiddenActivity, 'restore must not acknowledge mailbox rows or use device transfer')
    .toEqual([])
  await expect(restored.getByText(/start from scratch/i)).toHaveCount(0)
  await expect(restored.getByText(/request history|approve history|restore history/i)).toHaveCount(0)

  const restoredCursor = await backupCursor(restored)
  expect(restoredCursor).toBeGreaterThanOrEqual(cursorBeforeMessage + 1)
  expect(protectedAt).not.toMatch(/waiting/i)

  await restored.reload()
  await expect(bubble(restored, message)).toBeVisible({ timeout: 90_000 })

  await bubble(restored, message).hover()
  await bubble(restored, message).getByTestId('chat-reply-button').click()
  await expect(restored.getByTestId('chat-reply-composer')).toContainText(message)
  const reply = `reply-to-restored-history-${run}`
  await send(restored, reply)
  await expect(bubble(restored, reply)).toBeVisible()
  await expect(restored.getByTestId('chat-reply-context')).toContainText(message)
  await waitForProtection(restored, restoredCursor)

  await restored.reload()
  await expect(bubble(restored, reply)).toBeVisible({ timeout: 90_000 })
  await expect(restored.getByTestId('chat-reply-context')).toContainText(message)
  await restoredContext.close()
  recordSafeCheckpoint('single-history-recovery', 'reload-and-reply-persisted', { records: 2 })
})

test('protected media restores lazily and presents an unavailable state without partial import', async ({ browser }) => {
  test.slow()
  const run = `${Date.now().toString(36)}-${process.pid.toString(36)}`
  const account = newAccount('media', PASSWORD)
  const filename = `protected-media-${run}.txt`
  const sourceContext = await browser.newContext()
  recordSafeCheckpoint('single-media-recovery', 'source-context-created')
  await registerAccount(sourceContext, account)
  const source = await openChat(sourceContext)
  await openNoteToSelf(source)
  const cursorBeforeMedia = await backupCursor(source)
  await sendNoteAttachment(source, filename, `protected media ${run}`)
  await waitForProtection(source, cursorBeforeMedia)
  recordSafeCheckpoint('single-media-recovery', 'source-media-protected', { media: 1 })
  await sourceContext.close()

  const restoredContext = await browser.newContext()
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
  await signIn(restoredContext, account)
  const restored = await openChat(restoredContext)
  await openNoteToSelf(restored)
  await expect(bubble(restored, filename).getByText(filename, { exact: true })).toBeVisible({ timeout: 45_000 })
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
    'The encrypted attachment could not be downloaded.',
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
