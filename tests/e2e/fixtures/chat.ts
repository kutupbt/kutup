import { expect, type BrowserContext, type Page } from '@playwright/test'
import { appUrl, type Server } from './apps'

/**
 * Opens the Chat app on a signed-in context and waits until this browser's
 * chat device is registered (its id shows under Settings → Devices), then
 * returns to the conversation list.
 */
export async function openChat(
  context: BrowserContext,
  server: Server = 'primary',
  watch?: (page: Page) => void,
): Promise<Page> {
  const page = await context.newPage()
  watch?.(page)
  await page.goto(appUrl('chat', '/settings/devices', server))
  await expect(page.getByTestId('chat-device-status')).toHaveAttribute('data-device-id', /^\d+$/, { timeout: 120_000 })
  await openChats(page)
  return page
}

/** The sidebar's conversation list. */
export async function openChats(page: Page): Promise<void> {
  // After a reload Chat starts again (keys, mailbox, history) before its
  // navigation appears.
  await page.getByRole('link', { name: /^Chats/ }).click({ timeout: 60_000 })
  await expect(page.getByRole('region', { name: 'Conversations' })).toBeVisible({ timeout: 60_000 })
}

/** Chat settings, one section (Devices, History backup, …), in-app. */
export async function openSettings(page: Page, section: string): Promise<void> {
  await page.getByRole('link', { name: 'Settings', exact: true }).click()
  await page.getByRole('navigation', { name: 'Chat settings' }).getByRole('link', { name: section, exact: true }).click()
}

/** This browser's chat device id. */
export async function deviceId(page: Page): Promise<number> {
  await openSettings(page, 'Devices')
  const status = page.getByTestId('chat-device-status')
  await expect(status).toHaveAttribute('data-device-id', /^\d+$/, { timeout: 60_000 })
  const id = Number(await status.getAttribute('data-device-id'))
  await openChats(page)
  return id
}

export async function openNoteToSelf(page: Page): Promise<void> {
  await page.getByRole('button', { name: 'New chat' }).first().click()
  await page.getByRole('dialog').getByRole('button', { name: 'Note to Self' }).click()
  await expect(composer(page)).toBeVisible({ timeout: 60_000 })
}

/** Starts (or opens) a direct chat with `address`. */
export async function openDirectChat(page: Page, address: string): Promise<void> {
  await page.getByRole('button', { name: 'New chat' }).first().click()
  const dialog = page.getByRole('dialog')
  await dialog.getByRole('textbox').fill(address)
  await dialog.getByRole('textbox').press('Enter')
  await expect(composer(page)).toBeVisible({ timeout: 60_000 })
}

export function composer(page: Page) {
  return page.getByPlaceholder('Message', { exact: true })
}

/** Sends a text message with the keyboard, once the composer can send. */
export async function send(page: Page, text: string): Promise<void> {
  const input = composer(page)
  await input.fill(text)
  await expect(page.getByRole('button', { name: 'Send', exact: true })).toBeEnabled({ timeout: 45_000 })
  await input.press('Enter')
}

export function bubble(page: Page, text: string) {
  return page.getByTestId('chat-message').filter({ hasText: text })
}

/**
 * The message whose own text is exactly `text`: unlike bubble(), a reply
 * quoting it does not match.
 */
export function message(page: Page, text: string) {
  return page.getByTestId('chat-message').filter({ has: page.locator('p').getByText(text, { exact: true }) })
}

/** Opens the existing conversation whose row names `peer`. */
export async function openConversationWith(page: Page, peer: string): Promise<void> {
  await openChats(page)
  await page.getByRole('region', { name: 'Conversations' }).getByRole('link', { name: new RegExp(`^${peer.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`) }).first().click()
  await page.waitForURL(/\/c\/[^/]+$/, { timeout: 45_000 })
}

/** Accepts the open conversation's message request. */
export async function acceptRequest(page: Page): Promise<void> {
  const accept = page.getByRole('button', { name: 'Accept', exact: true })
  await accept.click()
  await expect(accept).toBeHidden({ timeout: 45_000 })
}

/** Opens a message's hover action (reply, reactions, more). */
async function hover(page: Page, text: string) {
  const target = message(page, text)
  await target.hover()
  return target
}

export async function replyTo(page: Page, target: string, text: string): Promise<void> {
  await (await hover(page, target)).getByTestId('chat-reply-button').click()
  await expect(page.getByTestId('chat-reply-composer')).toContainText(target)
  await send(page, text)
  await expect(message(page, text)).toBeVisible({ timeout: 45_000 })
}

export async function reactTo(page: Page, target: string, emoji: string): Promise<void> {
  await (await hover(page, target)).getByTestId('chat-reaction-button').click()
  await page.getByRole('menuitem', { name: `React with ${emoji}` }).click()
}

async function moreActions(page: Page, target: string): Promise<void> {
  await (await hover(page, target)).getByRole('button', { name: 'More actions' }).click()
}

export async function editMessage(page: Page, target: string, replacement: string): Promise<void> {
  await moreActions(page, target)
  await page.getByTestId('chat-edit-button').click()
  await expect(page.getByTestId('chat-edit-composer')).toBeVisible()
  await composer(page).fill(replacement)
  await composer(page).press('Enter')
  await expect(message(page, replacement)).toBeVisible({ timeout: 45_000 })
}

/** Deletes one of this person's own messages for everyone. */
export async function deleteForEveryone(page: Page, target: string): Promise<void> {
  const before = await page.getByTestId('chat-message-deleted').count()
  await moreActions(page, target)
  await page.getByTestId('chat-delete-button').click()
  await page.getByTestId('chat-delete-for-everyone').click()
  await expect(page.getByTestId('chat-message-deleted')).toHaveCount(before + 1, { timeout: 45_000 })
}

export function reaction(page: Page, target: string, emoji: string) {
  return message(page, target).locator(`[data-testid="chat-reaction-aggregate"][data-emoji="${emoji}"]`)
}

export async function enableReadReceipts(page: Page): Promise<void> {
  await openSettings(page, 'Privacy')
  await page.getByTestId('chat-read-receipts-toggle').check()
  await openChats(page)
}

/** Sets the open conversation's disappearing-message timer. */
export async function setDisappearing(page: Page, preset: 'off' | 'thirtySeconds'): Promise<void> {
  await page.getByTestId('chat-disappearing-timer').click()
  await page.getByTestId(`chat-disappearing-${preset}`).click()
}

/** Revokes every chat device of this account except this browser's own. */
export async function revokeOtherDevices(page: Page, expected: number): Promise<void> {
  await openSettings(page, 'Devices')
  const revoke = page.locator('[data-testid^="chat-device-revoke-"]')
  await expect(revoke).toHaveCount(expected, { timeout: 45_000 })
  for (let left = expected; left > 0; left--) {
    await revoke.first().click()
    await page.getByRole('alertdialog').getByRole('button', { name: 'Revoke', exact: true }).click()
    await expect(revoke).toHaveCount(left - 1, { timeout: 45_000 })
  }
  await openChats(page)
}

/** Sends a text file into the open conversation and waits for delivery. */
export async function sendAttachment(
  page: Page,
  filename: string,
  plaintext: string,
  { delivered = true }: { delivered?: boolean } = {},
): Promise<void> {
  // Note to Self keeps the file on this account: nothing is delivered.
  const delivery = delivered
    ? page.waitForResponse((response) => {
        const path = new URL(response.url()).pathname
        return response.request().method() === 'POST' && path === '/api/chat/media/deliveries'
      })
    : null
  await page.getByTestId('chat-attachment-input').setInputFiles({
    name: filename,
    mimeType: 'text/plain',
    buffer: Buffer.from(plaintext, 'utf8'),
  })
  if (delivery) expect((await delivery).ok()).toBe(true)
}

/** Opens the open conversation's details side panel. */
export async function openDetails(page: Page): Promise<void> {
  await page.getByRole('button', { name: 'Chat details' }).click()
  await expect(page.getByRole('region', { name: 'Chat details' })).toBeVisible()
}

/** Closes the details side panel if it is open. */
export async function closeDetails(page: Page): Promise<void> {
  const panel = page.getByRole('region', { name: 'Chat details' })
  if (!(await panel.isVisible())) return
  await panel.getByRole('button', { name: 'Back' }).click()
  await expect(panel).toBeHidden()
}

/** Opens a group from the conversation list. */
export async function openGroup(page: Page, conversationId: string): Promise<void> {
  await openChats(page)
  await page.getByTestId(`chat-group-${conversationId}`).click({ timeout: 90_000 })
  await page.waitForURL(/\/c\/group/, { timeout: 45_000 })
}

/**
 * Creates an MLS group with one first member and returns its conversation
 * id, from the genesis response.
 */
export async function createGroup(page: Page, member: string, name = 'Test group'): Promise<string> {
  const genesis = page.waitForResponse((response) => {
    const path = new URL(response.url()).pathname
    return response.request().method() === 'POST' && path === '/api/chat/mls/conversations'
  })
  await page.getByRole('button', { name: 'New chat' }).first().click()
  await page.getByRole('dialog').getByTestId('chat-create-group').click()
  await page.getByTestId('chat-group-name').fill(name)
  await page.getByTestId('chat-group-initial-member').fill(member)
  await page.getByTestId('chat-group-create-submit').click()
  const response = await genesis
  expect(response.ok()).toBe(true)
  return ((await response.json()) as { conversationId: string }).conversationId
}

/** Accepts a group invitation and opens the group. */
export async function acceptGroup(page: Page, conversationId: string): Promise<void> {
  await openChats(page)
  await expect(page.getByTestId('chat-group-invitations')).toBeVisible({ timeout: 90_000 })
  await page.getByTestId('chat-group-accept').first().click()
  await expect(page.getByTestId(`chat-group-${conversationId}`)).toBeVisible({ timeout: 90_000 })
  await page.getByTestId(`chat-group-${conversationId}`).click()
}

/** The backup cursor the server has acknowledged, read from Settings. */
export async function backupCursor(page: Page): Promise<number> {
  await openSettings(page, 'History backup')
  const status = page.getByTestId('chat-backup-state')
  await expect(status).toHaveAttribute('data-current-cursor', /^\d+$/, { timeout: 45_000 })
  const cursor = Number(await status.getAttribute('data-current-cursor'))
  await page.goBack()
  await page.goBack()
  return cursor
}

/**
 * Waits until the backup is protected past `afterCursor` and returns the
 * "Latest protected" line. Returns to the page it was opened from.
 */
export async function waitForProtection(page: Page, afterCursor: number): Promise<string> {
  await openSettings(page, 'History backup')
  const status = page.getByTestId('chat-backup-state')
  await expect(status).toHaveText('Protected', { timeout: 45_000 })
  await expect
    .poll(async () => Number(await status.getAttribute('data-current-cursor')), {
      timeout: 45_000,
      intervals: [250, 500, 1_000, 2_000],
    })
    .toBeGreaterThan(afterCursor)
  const latest = page.getByTestId('chat-backup-latest-protected')
  await expect(latest).not.toContainText(/waiting/i, { timeout: 45_000 })
  const text = (await latest.textContent())?.trim() ?? ''
  expect(text).not.toBe('')
  await page.goBack()
  await page.goBack()
  return text
}
