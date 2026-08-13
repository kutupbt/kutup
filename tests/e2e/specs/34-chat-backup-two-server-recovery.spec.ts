import { execFileSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'
import { expect, test, type BrowserContext, type Page } from '@playwright/test'
import { recordSafeCheckpoint } from '../safe-diagnostics'

const SECONDARY = process.env.E2E_SECONDARY_BASE_URL
const PASSWORD = 'Deneme123*FederatedBackupPassword'
const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../../..')
const COMPOSE = resolve(ROOT, 'docker-compose.chat-federation.yml')
const PROJECT = process.env.KUTUP_FEDERATION_PROJECT ?? 'kutup-chat-federation-test'

async function captureMnemonic(page: Page): Promise<string> {
  const text = await page.evaluate(() => document.body.innerText)
  const words = new Map<number, string>()
  for (const match of text.matchAll(/(?:^|\s)(\d{1,2})[.)]\s*([a-z]+)\b/gim)) {
    const index = Number(match[1])
    if (index >= 1 && index <= 24 && !words.has(index)) words.set(index, match[2])
  }
  const phrase = Array.from({ length: 24 }, (_, index) => words.get(index + 1))
  if (phrase.some(word => !word)) throw new Error('failed to capture recovery mnemonic')
  return phrase.join(' ')
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
  const phrase = await captureMnemonic(page)
  await page.getByRole('button', { name: /saved/i }).click()
  await page.locator('textarea').fill(phrase)
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
  await expect(page.getByTestId('chat-device-status')).toHaveText(/Device \d+/, { timeout: 90_000 })
}

async function send(page: Page, text: string): Promise<void> {
  const input = page.getByRole('main').getByRole('textbox')
  await input.fill(text)
  await expect(page.getByRole('button', { name: 'Send', exact: true })).toBeEnabled({ timeout: 45_000 })
  await input.press('Enter')
  await expect(page.getByRole('main').getByText(text, { exact: true })).toBeVisible()
}

async function syncUntilVisible(page: Page, text: string): Promise<void> {
  await expect.poll(async () => {
    if (await page.getByRole('main').getByText(text, { exact: true }).count() > 0) return true
    await page.getByRole('button', { name: 'Sync messages' }).click()
    return await page.getByRole('main').getByText(text, { exact: true }).count() > 0
  }, { timeout: 45_000, intervals: [500, 1_000, 2_000] }).toBe(true)
}

function message(page: Page, text: string) {
  return page.getByTestId('chat-message').filter({
    has: page.locator('p').getByText(text, { exact: true }),
  })
}

async function replyTo(page: Page, target: string, text: string): Promise<void> {
  await message(page, target).getByTestId('chat-reply-button').click()
  await expect(page.getByTestId('chat-reply-composer')).toContainText(target)
  await send(page, text)
}

async function reactTo(page: Page, target: string, emoji: string): Promise<void> {
  await message(page, target).getByTestId('chat-reaction-button').click()
  await page.getByRole('menuitem', { name: `React with ${emoji}` }).click()
}

async function editMessage(page: Page, target: string, replacement: string): Promise<void> {
  await message(page, target).getByTestId('chat-edit-button').click()
  await expect(page.getByTestId('chat-edit-composer')).toBeVisible()
  const input = page.getByRole('main').getByRole('textbox')
  await input.fill(replacement)
  await input.press('Enter')
  await expect(message(page, replacement)).toBeVisible({ timeout: 45_000 })
}

async function deleteMessage(page: Page, target: string): Promise<void> {
  page.once('dialog', dialog => void dialog.accept())
  await message(page, target).getByTestId('chat-delete-button').click()
  await expect(page.getByTestId('chat-message-deleted')).toBeVisible({ timeout: 45_000 })
}

async function syncUntilDeleted(page: Page): Promise<void> {
  await expect.poll(async () => {
    if (await page.getByTestId('chat-message-deleted').count() > 0) return true
    await page.getByRole('button', { name: 'Sync messages' }).click()
    return await page.getByTestId('chat-message-deleted').count() > 0
  }, { timeout: 45_000, intervals: [500, 1_000, 2_000] }).toBe(true)
}

async function syncUntilReaction(
  page: Page,
  target: string,
  emoji: string,
  count: number,
): Promise<void> {
  await expect.poll(async () => {
    const aggregate = message(page, target)
      .locator(`[data-testid="chat-reaction-aggregate"][data-emoji="${emoji}"]`)
    if (await aggregate.count() > 0
        && await aggregate.first().getAttribute('data-count') === String(count)) {
      return true
    }
    await page.getByRole('button', { name: 'Sync messages' }).click()
    return await aggregate.count() > 0
      && await aggregate.first().getAttribute('data-count') === String(count)
  }, { timeout: 45_000, intervals: [500, 1_000, 2_000] }).toBe(true)
}

async function enableReadReceipts(page: Page): Promise<void> {
  await page.getByTestId('chat-devices-button').click()
  await page.getByTestId('chat-read-receipts-toggle').check()
  await page.keyboard.press('Escape')
}

async function revokeLostChatDevices(page: Page): Promise<void> {
  await page.getByTestId('chat-devices-button').click()
  const revokeButtons = page.locator('[data-testid^="chat-device-revoke-"]')
  await expect(revokeButtons).toHaveCount(1, { timeout: 45_000 })
  page.once('dialog', dialog => void dialog.accept())
  await revokeButtons.first().click()
  await expect(revokeButtons).toHaveCount(0, { timeout: 45_000 })
  await page.keyboard.press('Escape')
}

async function syncUntilReceipt(page: Page, target: string): Promise<void> {
  await expect.poll(async () => {
    const receipt = message(page, target).getByTestId('chat-receipt-read')
    if (await receipt.count() > 0) return true
    await page.getByRole('button', { name: 'Sync messages' }).click()
    return await receipt.count() > 0
  }, { timeout: 45_000, intervals: [500, 1_000, 2_000] }).toBe(true)
}

async function sendAttachment(page: Page, filename: string, plaintext: string): Promise<void> {
  const receipt = page.waitForResponse(response => {
    const path = new URL(response.url()).pathname
    return response.request().method() === 'POST' && path === '/api/chat/media/deliveries'
  })
  await page.getByTestId('chat-attachment-input').setInputFiles({
    name: filename,
    mimeType: 'text/plain',
    buffer: Buffer.from(plaintext, 'utf8'),
  })
  expect((await receipt).ok()).toBe(true)
}

async function syncUntilAttachment(page: Page, filename: string): Promise<void> {
  await expect.poll(async () => {
    if (await page.getByText(filename, { exact: true }).count() > 0) return true
    await page.getByRole('button', { name: 'Sync messages' }).click()
    return await page.getByText(filename, { exact: true }).count() > 0
  }, { timeout: 90_000, intervals: [500, 1_000, 2_000] }).toBe(true)
}

async function setDisappearing(page: Page, enabled: boolean): Promise<void> {
  await page.getByTestId('chat-disappearing-timer').click()
  await page.getByTestId(enabled
    ? 'chat-disappearing-thirtySeconds'
    : 'chat-disappearing-off').click()
}

async function backupCursor(page: Page): Promise<number> {
  await page.getByTestId('chat-devices-button').click()
  const status = page.getByTestId('chat-backup-state')
  await expect(status).toHaveAttribute('data-current-cursor', /^\d+$/, { timeout: 45_000 })
  const cursor = Number(await status.getAttribute('data-current-cursor'))
  await page.keyboard.press('Escape')
  return cursor
}

async function waitForProtection(page: Page, afterCursor: number): Promise<void> {
  await page.getByTestId('chat-devices-button').click()
  const status = page.getByTestId('chat-backup-state')
  await expect(status).toHaveText('Protected', { timeout: 45_000 })
  await expect.poll(async () => Number(await status.getAttribute('data-current-cursor')), {
    timeout: 45_000,
    intervals: [250, 500, 1_000, 2_000],
  }).toBeGreaterThan(afterCursor)
  await expect(page.getByTestId('chat-backup-latest-protected'))
    .not.toContainText(/waiting/i, { timeout: 45_000 })
  await page.keyboard.press('Escape')
}

async function openDirectConversation(page: Page, username: string): Promise<void> {
  await page.locator('aside').getByRole('button', { name: new RegExp(username) }).click()
}

function compose(args: string[]): string {
  return execFileSync('docker', [
    'compose', '--project-name', PROJECT, '--file', COMPOSE, ...args,
  ], { cwd: ROOT, encoding: 'utf8' }).trim()
}

async function restartHomeservers(
  baseURL: string,
  secondary: string,
  accounts: Array<{
    baseURL: string
    postgres: 'postgres-a' | 'postgres-b'
    email: string
    username: string
  }>,
): Promise<void> {
  const expectedSalts = accounts.map(account => ({
    ...account,
    salt: accountProtectionSalt(account.postgres, account.username),
  }))
  // Docker reconnects simultaneously restarted containers to the network in
  // nondeterministic order. Starting nginx in that window can pin backend-a
  // to backend-b's former address (and vice versa) until the next reload.
  // Settle the backend addresses before either edge resolves its upstream.
  compose(['restart', 'backend-a', 'backend-b'])
  compose(['up', '--detach', '--wait', 'backend-a', 'backend-b'])
  compose(['restart', 'edge-a', 'edge-b'])
  for (const url of [`${baseURL}/api/health`, `${secondary}/api/health`]) {
    await expect.poll(async () => {
      try { return (await fetch(url)).ok } catch { return false }
    }, { timeout: 60_000, intervals: [500, 1_000, 2_000] }).toBe(true)
  }
  for (const account of expectedSalts) {
    await expect.poll(async () => {
      try {
        const response = await fetch(
          `${account.baseURL}/api/auth/login/preflight?email=${encodeURIComponent(account.email)}`,
        )
        if (!response.ok) return false
        const preflight = await response.json() as { accountProtectionSalt?: string }
        return preflight.accountProtectionSalt === account.salt
      } catch {
        return false
      }
    }, {
      timeout: 60_000,
      intervals: [500, 1_000, 2_000],
      message: `restarted ${account.postgres} did not expose its persisted account`,
    }).toBe(true)
  }
}

function backupRows(postgres: 'postgres-a' | 'postgres-b', username: string): number {
  const quoted = username.replaceAll("'", "''")
  const sql = `SELECT COUNT(*) FROM chat_backups b JOIN users u ON u.id=b.user_id WHERE u.username='${quoted}'`
  return Number(compose(['exec', '-T', postgres, 'psql', '-U', 'kutup', '-d', 'kutup', '-Atc', sql]))
}

function accountProtectionSalt(
  postgres: 'postgres-a' | 'postgres-b',
  username: string,
): string {
  const quoted = username.replaceAll("'", "''")
  return compose([
    'exec', '-T', postgres, 'psql', '-U', 'kutup', '-d', 'kutup', '-Atc',
    `SELECT account_protection_salt FROM users WHERE username='${quoted}'`,
  ])
}

function backupFacts(
  postgres: 'postgres-a' | 'postgres-b',
  username: string,
): { backups: number; objects: number; media: number } {
  const quoted = username.replaceAll("'", "''")
  const sql = `SELECT COUNT(*),
    (SELECT COUNT(*) FROM chat_backup_segments s WHERE s.user_id=u.id) +
    (SELECT COUNT(*) FROM chat_backup_bases b WHERE b.user_id=u.id) +
    (SELECT COUNT(*) FROM chat_backup_media_objects m WHERE m.user_id=u.id),
    (SELECT COUNT(*) FROM chat_backup_media_objects m WHERE m.user_id=u.id)
    FROM users u JOIN chat_backups cb ON cb.user_id=u.id
    WHERE u.username='${quoted}' GROUP BY u.id`
  const output = compose(['exec', '-T', postgres, 'psql', '-U', 'kutup', '-d', 'kutup', '-Atc', sql])
  if (!output) return { backups: 0, objects: 0, media: 0 }
  const [backups, objects, media] = output.split('|').map(Number)
  return { backups, objects, media }
}

test.describe('two-server continuous backup recovery', () => {
  test.skip(!SECONDARY, 'set E2E_SECONDARY_BASE_URL for the federation topology')

  test('both account-local histories survive total browser loss and server restart', async ({
    browser,
    baseURL,
  }) => {
    test.slow()
    if (!baseURL || !SECONDARY) throw new Error('two-server base URLs are required')
    const tag = Date.now().toString(36)
    const alice = `backupalice${tag}`.slice(0, 32)
    const bob = `backupbob${tag}`.slice(0, 32)
    const aliceEmail = `${alice}@a.test`
    const bobEmail = `${bob}@b.test`
    const sourceA = await browser.newContext({ baseURL })
    const sourceB = await browser.newContext({ baseURL: SECONDARY })
    recordSafeCheckpoint('two-server-recovery', 'source-contexts-created', { accounts: 2 })
    await register(sourceA, aliceEmail, alice)
    await register(sourceB, bobEmail, bob)
    const pageA = await login(sourceA, aliceEmail)
    const pageB = await login(sourceB, bobEmail)
    await openChat(pageA)
    await openChat(pageB)
    await enableReadReceipts(pageB)

    await pageA.getByPlaceholder('Username').fill(`${bob}@b.test`)
    await pageA.getByRole('button', { name: 'Start chat' }).click()
    const directOriginal = `direct-before-loss-a-${tag}`
    await send(pageA, directOriginal)
    await expect(pageB.getByText('1 message request')).toBeVisible({ timeout: 45_000 })
    await openDirectConversation(pageB, alice)
    await expect(pageB.getByRole('main').getByText(directOriginal, { exact: true })).toBeVisible()
    const accept = pageB.getByRole('button', { name: 'Accept', exact: true })
    await accept.click()
    await expect(accept).toBeHidden({ timeout: 45_000 })
    await syncUntilReceipt(pageA, directOriginal)

    const directReply = `direct-reply-${tag}`
    await replyTo(pageB, directOriginal, directReply)
    await syncUntilVisible(pageA, directReply)
    await reactTo(pageB, directOriginal, '👍')
    await syncUntilReaction(pageA, directOriginal, '👍', 1)
    const editedDirect = `direct-edited-${tag}`
    await editMessage(pageA, directOriginal, editedDirect)
    await syncUntilVisible(pageB, editedDirect)

    const deletedDirect = `direct-deleted-${tag}`
    await send(pageA, deletedDirect)
    await syncUntilVisible(pageB, deletedDirect)
    await deleteMessage(pageA, deletedDirect)
    await syncUntilDeleted(pageB)

    const directAttachment = `direct-protected-${tag}.txt`
    await sendAttachment(pageA, directAttachment, `direct protected media ${tag}`)
    await syncUntilAttachment(pageB, directAttachment)

    await setDisappearing(pageA, true)
    await expect.poll(async () => {
      const timer = pageB.getByTestId('chat-disappearing-timer')
      if (await timer.getAttribute('title') === 'New messages disappear after 30 seconds') return true
      await pageB.getByRole('button', { name: 'Sync messages' }).click()
      return await timer.getAttribute('title') === 'New messages disappear after 30 seconds'
    }, { timeout: 45_000, intervals: [500, 1_000, 2_000] }).toBe(true)
    const expiredDirect = `direct-expired-${tag}`
    await send(pageA, expiredDirect)
    await syncUntilVisible(pageB, expiredDirect)
    await expect.poll(async () => ({
      alice: await message(pageA, expiredDirect).count(),
      bob: await message(pageB, expiredDirect).count(),
    }), { timeout: 45_000, intervals: [1_000, 2_000] }).toEqual({ alice: 0, bob: 0 })
    await setDisappearing(pageA, false)

    const genesisResponse = pageA.waitForResponse(response => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'POST' && path === '/api/chat/mls/conversations'
    })
    await pageA.getByTestId('chat-create-group').click()
    await pageA.getByTestId('chat-group-initial-member').fill(`${bob}@b.test`)
    await pageA.getByTestId('chat-group-create-submit').click()
    const genesis = await genesisResponse
    expect(genesis.ok()).toBe(true)
    const { conversationId } = await genesis.json() as { conversationId: string }
    await expect(pageB.getByTestId('chat-group-invitations')).toBeVisible({ timeout: 90_000 })
    await pageB.getByTestId('chat-group-accept').click()
    await expect(pageB.getByTestId(`chat-group-${conversationId}`)).toBeVisible({ timeout: 90_000 })
    await expect(pageA.getByTestId('chat-group-delivery-readiness')).toHaveCount(0, {
      timeout: 90_000,
    })

    const mlsFromAlice = `mls-before-loss-a-${tag}`
    await send(pageA, mlsFromAlice)
    await syncUntilVisible(pageB, mlsFromAlice)
    const mlsFromBob = `mls-before-loss-b-${tag}`
    await send(pageB, mlsFromBob)
    await syncUntilVisible(pageA, mlsFromBob)
    const mlsReply = `mls-reply-${tag}`
    await replyTo(pageB, mlsFromAlice, mlsReply)
    await syncUntilVisible(pageA, mlsReply)
    await reactTo(pageB, mlsFromAlice, '❤️')
    await syncUntilReaction(pageA, mlsFromAlice, '❤️', 1)
    const editedMls = `mls-edited-${tag}`
    await editMessage(pageB, mlsFromBob, editedMls)
    await syncUntilVisible(pageA, editedMls)
    const deletedMls = `mls-deleted-${tag}`
    await send(pageA, deletedMls)
    await syncUntilVisible(pageB, deletedMls)
    const bobDeletedBefore = await pageB.getByTestId('chat-message-deleted').count()
    await deleteMessage(pageA, deletedMls)
    await expect.poll(async () => {
      await pageB.getByRole('button', { name: 'Sync messages' }).click()
      return await pageB.getByTestId('chat-message-deleted').count()
    }, { timeout: 45_000, intervals: [500, 1_000, 2_000] }).toBeGreaterThan(bobDeletedBefore)
    const [aliceCursorBeforeFinalMutation, bobCursorBeforeFinalMutation] = await Promise.all([
      backupCursor(pageA),
      backupCursor(pageB),
    ])
    const mlsAttachment = `mls-protected-${tag}.txt`
    await sendAttachment(pageA, mlsAttachment, `MLS protected media ${tag}`)
    await syncUntilAttachment(pageB, mlsAttachment)

    await waitForProtection(pageA, aliceCursorBeforeFinalMutation)
    await waitForProtection(pageB, bobCursorBeforeFinalMutation)
    recordSafeCheckpoint('two-server-recovery', 'both-accounts-protected', { accounts: 2 })

    const aliceOwn = backupFacts('postgres-a', alice)
    const bobOwn = backupFacts('postgres-b', bob)
    expect(aliceOwn).toMatchObject({ backups: 1 })
    expect(aliceOwn.objects).toBeGreaterThan(0)
    expect(aliceOwn.media).toBeGreaterThan(0)
    expect(bobOwn).toMatchObject({ backups: 1 })
    expect(bobOwn.objects).toBeGreaterThan(0)
    expect(bobOwn.media).toBeGreaterThan(0)
    expect(backupFacts('postgres-a', bob)).toEqual({ backups: 0, objects: 0, media: 0 })
    expect(backupFacts('postgres-b', alice)).toEqual({ backups: 0, objects: 0, media: 0 })
    recordSafeCheckpoint('two-server-recovery', 'account-locality-verified', {
      accounts: 2,
      media: aliceOwn.media + bobOwn.media,
      objects: aliceOwn.objects + bobOwn.objects,
    })
    await sourceA.close()
    await sourceB.close()
    recordSafeCheckpoint('two-server-recovery', 'all-source-browsers-lost', { accounts: 2 })
    expect(backupRows('postgres-a', alice), 'closing Alice browser must not remove her account')
      .toBe(1)
    expect(backupRows('postgres-b', bob), 'closing Bob browser must not remove his account')
      .toBe(1)
    await restartHomeservers(baseURL, SECONDARY, [
      { baseURL, postgres: 'postgres-a', email: aliceEmail, username: alice },
      { baseURL: SECONDARY, postgres: 'postgres-b', email: bobEmail, username: bob },
    ])
    expect(backupRows('postgres-a', alice), 'Alice account must survive homeserver restart')
      .toBe(1)
    expect(backupRows('postgres-b', bob), 'Bob account must survive homeserver restart')
      .toBe(1)
    recordSafeCheckpoint('two-server-recovery', 'homeservers-restarted', { accounts: 2 })

    const cleanA = await browser.newContext({ baseURL })
    const cleanB = await browser.newContext({ baseURL: SECONDARY })
    const transferRequests: string[] = []
    const mediaGetsA: string[] = []
    const mediaGetsB: string[] = []
    await cleanA.route('**/api/chat/media/objects/*', route => route.fulfill({ status: 404 }))
    await cleanB.route('**/api/chat/media/objects/*', route => route.fulfill({ status: 404 }))
    for (const context of [cleanA, cleanB]) {
      context.on('request', request => {
        if (request.url().includes('history-transfer')) transferRequests.push(request.url())
        const path = new URL(request.url()).pathname
        if (request.method() === 'GET' && path.includes('/chat/backup/media/')) {
          (context === cleanA ? mediaGetsA : mediaGetsB).push(path)
        }
      })
    }
    const restoredA = await login(cleanA, aliceEmail)
    const restoredB = await login(cleanB, bobEmail)
    await openChat(restoredA)
    await openChat(restoredB)
    await openDirectConversation(restoredA, bob)
    await openDirectConversation(restoredB, alice)
    const [aliceCursorBeforeFreshMessages, bobCursorBeforeFreshMessages] = await Promise.all([
      backupCursor(restoredA),
      backupCursor(restoredB),
    ])
    for (const page of [restoredA, restoredB]) {
      await expect(message(page, editedDirect)).toBeVisible()
      await expect(message(page, directReply).getByTestId('chat-reply-context'))
        .toContainText(editedDirect)
      await expect(message(page, editedDirect)
        .locator('[data-testid="chat-reaction-aggregate"][data-emoji="👍"]'))
        .toHaveAttribute('data-count', '1')
      await expect(page.getByText(deletedDirect, { exact: true })).toHaveCount(0)
      await expect(page.getByText(expiredDirect, { exact: true })).toHaveCount(0)
      await expect(page.getByRole('main').getByText(directAttachment, { exact: true }))
        .toBeVisible()
    }
    await expect(message(restoredA, editedDirect).getByTestId('chat-receipt-read')).toBeVisible()
    expect(mediaGetsA).toEqual([])
    expect(mediaGetsB).toEqual([])
    const directProtectedDownload = restoredB.waitForResponse(response => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'GET'
        && path.includes('/api/chat/backup/media/') && response.ok()
    })
    await restoredB.getByRole('button', {
      name: `Download ${directAttachment} into Kutup`,
    }).click()
    await directProtectedDownload
    await expect(restoredB.getByRole('button', {
      name: `${directAttachment} is available in Kutup`,
    })).toBeVisible({ timeout: 45_000 })

    await restoredA.getByTestId(`chat-group-${conversationId}`).click()
    await restoredB.getByTestId(`chat-group-${conversationId}`).click()
    for (const page of [restoredA, restoredB]) {
      await expect(message(page, mlsFromAlice)).toBeVisible()
      await expect(message(page, editedMls)).toBeVisible()
      await expect(message(page, mlsReply).getByTestId('chat-reply-context'))
        .toContainText(mlsFromAlice)
      await expect(message(page, mlsFromAlice)
        .locator('[data-testid="chat-reaction-aggregate"][data-emoji="❤️"]'))
        .toHaveAttribute('data-count', '1')
      await expect(page.getByText(deletedMls, { exact: true })).toHaveCount(0)
      await expect(page.getByRole('main').getByText(mlsAttachment, { exact: true }))
        .toBeVisible({ timeout: 45_000 })
    }
    const mlsProtectedDownload = restoredA.waitForResponse(response => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'GET'
        && path.includes('/api/chat/backup/media/') && response.ok()
    })
    await restoredA.getByRole('button', {
      name: `Download ${mlsAttachment} into Kutup`,
    }).click()
    await mlsProtectedDownload
    recordSafeCheckpoint('two-server-recovery', 'direct-and-mls-restored', {
      accounts: 2,
      media: 2,
    })
    expect(transferRequests).toEqual([])
    expect(backupFacts('postgres-a', alice).objects).toBeGreaterThan(0)
    expect(backupFacts('postgres-b', bob).objects).toBeGreaterThan(0)
    expect(backupFacts('postgres-a', bob)).toEqual({ backups: 0, objects: 0, media: 0 })
    expect(backupFacts('postgres-b', alice)).toEqual({ backups: 0, objects: 0, media: 0 })

    // A closed browser remains a signed account device until the recovered
    // account explicitly revokes it. MLS intentionally requires a fresh
    // KeyPackage for every signed destination device, so retire both lost
    // devices before proving that the recovered devices can form new state.
    await revokeLostChatDevices(restoredA)
    await revokeLostChatDevices(restoredB)

    await openDirectConversation(restoredA, bob)
    await openDirectConversation(restoredB, alice)
    const directAfterRestore = `direct-after-restore-${tag}`
    await send(restoredA, directAfterRestore)
    await syncUntilVisible(restoredB, directAfterRestore)

    const freshGenesisResponse = restoredA.waitForResponse(response => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'POST' && path === '/api/chat/mls/conversations'
    })
    await restoredA.getByTestId('chat-create-group').click()
    await restoredA.getByTestId('chat-group-initial-member').fill(`${bob}@b.test`)
    await restoredA.getByTestId('chat-group-create-submit').click()
    const freshGenesis = await freshGenesisResponse
    expect(freshGenesis.ok()).toBe(true)
    const freshConversationId = (await freshGenesis.json() as { conversationId: string })
      .conversationId
    await expect(restoredB.getByTestId('chat-group-invitations')).toBeVisible({ timeout: 90_000 })
    await restoredB.getByTestId('chat-group-accept').click()
    await expect(restoredB.getByTestId(`chat-group-${freshConversationId}`))
      .toBeVisible({ timeout: 90_000 })
    await expect(restoredA.getByTestId('chat-group-delivery-readiness')).toHaveCount(0, {
      timeout: 90_000,
    })
    const mlsAfterRestore = `mls-after-restore-${tag}`
    await send(restoredB, mlsAfterRestore)
    await syncUntilVisible(restoredA, mlsAfterRestore)
    await waitForProtection(restoredA, aliceCursorBeforeFreshMessages)
    await waitForProtection(restoredB, bobCursorBeforeFreshMessages)
    await cleanA.close()
    await cleanB.close()
    recordSafeCheckpoint('two-server-recovery', 'post-restore-messaging-protected', {
      accounts: 2,
      conversations: 2,
    })
  })
})
