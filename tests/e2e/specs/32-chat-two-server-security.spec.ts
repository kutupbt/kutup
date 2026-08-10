import { expect, test, type Browser, type BrowserContext, type Page } from '@playwright/test'

const SECONDARY = process.env.E2E_SECONDARY_BASE_URL
const PASSWORD = 'Deneme123*FederatedSecurityPassword'
const pageErrors = new WeakMap<Page, string[]>()

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
  const errors: string[] = []
  pageErrors.set(page, errors)
  page.on('pageerror', error => errors.push(error.stack ?? error.message))
  await page.goto('/chat')
  await expect(page.getByRole('heading', { name: 'Messages' })).toBeVisible({ timeout: 90_000 })
  await expect(page.getByTestId('chat-device-status')).toHaveText(/Device \d+/, { timeout: 90_000 })
  const headerLayout = await page.evaluate(() => {
    const header = document.querySelector<HTMLElement>('[data-testid="chat-sidebar-header"]')
    const title = document.querySelector<HTMLElement>('[data-testid="chat-sidebar-title"]')
    const device = document.querySelector<HTMLElement>('[data-testid="chat-device-status"]')
    if (!header || !title || !device) throw new Error('Chat sidebar header is incomplete')
    const headerBox = header.getBoundingClientRect()
    const titleBox = title.getBoundingClientRect()
    const deviceBox = device.getBoundingClientRect()
    return {
      headerLeft: headerBox.left,
      headerRight: headerBox.right,
      titleLeft: titleBox.left,
      titleRight: titleBox.right,
      deviceLeft: deviceBox.left,
      deviceRight: deviceBox.right,
      titleClientWidth: title.clientWidth,
      titleScrollWidth: title.scrollWidth,
      titleOverflowX: getComputedStyle(title).overflowX,
    }
  })
  expect(headerLayout.titleOverflowX).toBe('hidden')
  expect(headerLayout.titleScrollWidth).toBeLessThanOrEqual(headerLayout.titleClientWidth)
  expect(headerLayout.titleLeft).toBeGreaterThanOrEqual(headerLayout.headerLeft)
  expect(headerLayout.deviceLeft).toBeGreaterThanOrEqual(headerLayout.headerLeft)
  expect(headerLayout.titleRight).toBeLessThanOrEqual(headerLayout.headerRight)
  expect(headerLayout.deviceRight).toBeLessThanOrEqual(headerLayout.headerRight)
}

async function expectWasmRuntimeRevalidation(page: Page): Promise<void> {
  for (const path of [
    '/chat-wasm/kutup_chat_core.js?runtime=2',
    '/chat-wasm/kutup_chat_core_bg.wasm?runtime=2',
    '/crypto-wasm/kutup_crypto_wasm.js?runtime=2',
    '/crypto-wasm/kutup_crypto_wasm_bg.wasm?runtime=2',
  ]) {
    const response = await page.context().request.head(path)
    expect(response.ok(), `${path} must be deployed with the page`).toBe(true)
    const cacheControl = response.headers()['cache-control'] ?? ''
    expect(cacheControl, `${path} must revalidate`).toContain('no-cache')
    expect(cacheControl, `${path} must not be immutable`).not.toContain('immutable')
  }
}

function expectNoPageErrors(...pages: Page[]): void {
  expect(pages.flatMap(page => pageErrors.get(page) ?? [])).toEqual([])
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

async function send(page: Page, text: string): Promise<void> {
  const input = page.getByRole('main').getByRole('textbox')
  await input.fill(text)
  // Wait out the application's own transition, then use the keyboard submit
  // path so a transient bottom-right success toast cannot intercept it.
  const button = page.getByRole('button', { name: 'Send', exact: true })
  await expect(button).toBeEnabled({ timeout: 45_000 })
  await input.press('Enter')
}

async function replyTo(page: Page, target: string, text: string): Promise<void> {
  const message = page.getByTestId('chat-message').filter({ hasText: target })
  await message.getByTestId('chat-reply-button').click()
  await expect(page.getByTestId('chat-reply-composer')).toContainText(target)
  await send(page, text)
}

async function reactTo(page: Page, target: string, emoji: string): Promise<void> {
  const message = reactionTarget(page, target)
  await message.getByTestId('chat-reaction-button').click()
  await page.getByRole('menuitem', { name: `React with ${emoji}` }).click()
}

async function editMessage(page: Page, target: string, replacement: string): Promise<void> {
  await reactionTarget(page, target).getByTestId('chat-edit-button').click()
  await expect(page.getByTestId('chat-edit-composer')).toBeVisible()
  const input = page.getByRole('main').getByRole('textbox')
  await input.fill(replacement)
  await input.press('Enter')
  await expect(reactionTarget(page, replacement)).toBeVisible({ timeout: 45_000 })
}

async function deleteMessage(page: Page, target: string): Promise<void> {
  page.once('dialog', dialog => void dialog.accept())
  await reactionTarget(page, target).getByTestId('chat-delete-button').click()
  await expect(page.getByTestId('chat-message-deleted')).toBeVisible({ timeout: 45_000 })
}

async function syncUntilDeleted(page: Page): Promise<void> {
  await expect.poll(async () => {
    if (await page.getByTestId('chat-message-deleted').count() > 0) return true
    await page.getByRole('button', { name: 'Sync messages' }).click()
    await page.waitForTimeout(500)
    return await page.getByTestId('chat-message-deleted').count() > 0
  }, {
    timeout: 45_000,
    intervals: [500, 1_000, 2_000],
    message: 'encrypted message tombstone was not reconciled',
  }).toBe(true)
}

async function enableReadReceipts(page: Page): Promise<void> {
  await page.getByTestId('chat-devices-button').click()
  await page.getByTestId('chat-read-receipts-toggle').check()
  await page.keyboard.press('Escape')
}

async function syncUntilReceipt(
  page: Page,
  target: string,
  testId: 'chat-receipt-delivered' | 'chat-receipt-read',
): Promise<void> {
  await expect.poll(async () => {
    const receipt = reactionTarget(page, target).getByTestId(testId)
    if (await receipt.count() > 0) return true
    await page.getByRole('button', { name: 'Sync messages' }).click()
    await page.waitForTimeout(500)
    return await receipt.count() > 0
  }, {
    timeout: 45_000,
    intervals: [500, 1_000, 2_000],
    message: `encrypted receipt ${testId} was not reconciled`,
  }).toBe(true)
}

async function syncUntilReaction(
  page: Page,
  target: string,
  emoji: string,
  count: number,
): Promise<void> {
  const aggregate = () => reactionTarget(page, target)
    .locator(`[data-testid="chat-reaction-aggregate"][data-emoji="${emoji}"]`)
  await expect.poll(async () => {
    const chip = aggregate()
    if (await chip.count() > 0 && await chip.first().textContent() === `${emoji} ${count}`) return true
    await page.getByRole('button', { name: 'Sync messages' }).click()
    await page.waitForTimeout(500)
    return await chip.count() > 0 && await chip.first().textContent() === `${emoji} ${count}`
  }, {
    timeout: 45_000,
    intervals: [500, 1_000, 2_000],
    message: `encrypted ${emoji} reaction count ${count} was not reconciled`,
  }).toBe(true)
}

function reactionTarget(page: Page, target: string) {
  return page.getByTestId('chat-message').filter({
    has: page.locator('p').getByText(target, { exact: true }),
  })
}

async function syncUntilVisible(page: Page, text: string): Promise<void> {
  await expect.poll(async () => {
    if (await bubble(page, text).count() > 0) return true
    await page.getByRole('button', { name: 'Sync messages' }).click()
    await page.waitForTimeout(500)
    return await bubble(page, text).count() > 0
  }, {
    timeout: 45_000,
    intervals: [500, 1_000, 2_000],
    message: `durable message ${text} was not recovered by mailbox reconciliation`,
  }).toBe(true)
}

async function sendAttachment(
  page: Page,
  filename: string,
  plaintext: string,
  expectsDeliveryReceipt = true,
): Promise<void> {
  const receipt = expectsDeliveryReceipt ? page.waitForResponse((response) => {
    const path = new URL(response.url()).pathname
    return response.request().method() === 'POST'
      && path === '/api/chat/media/deliveries'
  }) : null
  await page.getByTestId('chat-attachment-input').setInputFiles({
    name: filename,
    mimeType: 'text/plain',
    buffer: Buffer.from(plaintext, 'utf8'),
  })
  if (receipt) expect((await receipt).ok()).toBe(true)
}

async function syncUntilAttachment(page: Page, filename: string): Promise<void> {
  await expect.poll(async () => {
    if (await page.getByText(filename, { exact: true }).count() > 0) return true
    await page.getByRole('button', { name: 'Sync messages' }).click()
    await page.waitForTimeout(500)
    return await page.getByText(filename, { exact: true }).count() > 0
  }, {
    timeout: 90_000,
    intervals: [500, 1_000, 2_000],
    message: `encrypted attachment ${filename} was not reconciled`,
  }).toBe(true)
}

async function downloadAttachment(page: Page, filename: string): Promise<string> {
  // Chromium exposes the File System Access API, so Kutup correctly streams
  // decrypted chunks into a picker-backed writable instead of building a
  // Blob download. Install a deterministic in-memory picker: this exercises
  // the production streaming path and lets the test compare exact plaintext
  // without relying on a host save dialog.
  await page.evaluate(() => {
    type DownloadCapture = Window & {
      __kutupDownloadChunks?: number[][]
      __kutupDownloadComplete?: boolean
      showSaveFilePicker?: () => Promise<{
        createWritable(): Promise<{
          write(data: BufferSource): Promise<void>
          close(): Promise<void>
          abort(): Promise<void>
        }>
      }>
    }
    const target = window as DownloadCapture
    target.__kutupDownloadChunks = []
    target.__kutupDownloadComplete = false
    target.showSaveFilePicker = async () => ({
      createWritable: async () => ({
        write: async (data) => {
          const view = data instanceof ArrayBuffer
            ? new Uint8Array(data)
            : new Uint8Array(data.buffer, data.byteOffset, data.byteLength)
          target.__kutupDownloadChunks!.push(Array.from(view))
        },
        close: async () => {
          target.__kutupDownloadComplete = true
        },
        abort: async () => {
          target.__kutupDownloadComplete = false
        },
      }),
    })
  })
  await page.getByRole('button', { name: `Download ${filename}` }).click()
  await expect.poll(
    () => page.evaluate(() => (
      window as Window & { __kutupDownloadComplete?: boolean }
    ).__kutupDownloadComplete === true),
    { timeout: 45_000, message: `download ${filename} did not finish` },
  ).toBe(true)
  return page.evaluate(() => {
    const chunks = (
      window as Window & { __kutupDownloadChunks?: number[][] }
    ).__kutupDownloadChunks ?? []
    const byteLength = chunks.reduce((sum, chunk) => sum + chunk.length, 0)
    const plaintext = new Uint8Array(byteLength)
    let offset = 0
    for (const chunk of chunks) {
      plaintext.set(chunk, offset)
      offset += chunk.length
    }
    return new TextDecoder().decode(plaintext)
  })
}

async function requireResponseOrUiError(
  page: Page,
  response: Promise<import('@playwright/test').Response>,
): Promise<import('@playwright/test').Response> {
  const uiError = page.locator('[data-sonner-toast][data-type="error"]')
  const errorText = uiError.waitFor({ state: 'visible', timeout: 15_000 })
    .then(async () => (await uiError.textContent())?.trim() || 'unknown error')
    .catch(() => undefined)
  const first = await Promise.race([
    response.then(value => ({ kind: 'response' as const, value })),
    errorText.then(value => ({ kind: 'error' as const, value })),
  ])
  if (first.kind === 'error') {
    throw new Error(`browser operation failed: ${first.value ?? 'unknown error'}`)
  }
  // The orderer acknowledgement precedes the initiating client's durable
  // OpenMLS merge. Keep observing the UI briefly so a post-ack cryptographic
  // or state failure cannot be mistaken for a successful operation.
  const lateError = await Promise.race([
    errorText,
    page.waitForTimeout(1_000).then(() => undefined),
  ])
  if (lateError) throw new Error(`browser operation failed: ${lateError}`)
  return first.value
}

function bubble(page: Page, text: string) {
  return page.getByRole('main').getByText(text, { exact: true })
}

async function closeGroupMembers(page: Page): Promise<void> {
  const dialog = page.getByRole('dialog', { name: 'MLS group members' })
  if (!await dialog.isVisible()) return
  await dialog.getByRole('button', { name: 'Close', exact: true }).click()
  await expect(dialog).toBeHidden()
}

test.describe('two-server secure chat', () => {
  test.skip(!SECONDARY, 'set E2E_SECONDARY_BASE_URL for the isolated federation topology')

  test('verifies the account pair, establishes sealed delivery, rotates capability, and never falls back', async ({ browser, baseURL }) => {
    test.slow()
    if (!baseURL || !SECONDARY) throw new Error('two-server base URLs are required')
    const abandonedContextA = await browser.newContext({ baseURL })
    const contextB = await browser.newContext({ baseURL: SECONDARY })
    const tag = Date.now() % 1_000_000
    const alice = `sealalice${tag}`
    const bob = `sealbob${tag}`
    const aliceEmail = `${alice}@example.test`
    const bobEmail = `${bob}@example.test`

    await register(abandonedContextA, aliceEmail, alice)
    await register(contextB, bobEmail, bob)
    const abandonedPageA = await login(abandonedContextA, aliceEmail)
    let interruptedManifestAttempts = 0
    await abandonedPageA.route('**/api/chat/manifest', async (route) => {
      if (route.request().method() === 'POST') {
        interruptedManifestAttempts += 1
        await route.abort('connectionfailed')
        return
      }
      await route.continue()
    })
    await abandonedPageA.goto('/chat')
    await expect(abandonedPageA.getByText('Secure chat is temporarily unavailable.')).toBeVisible({
      timeout: 90_000,
    })
    expect(interruptedManifestAttempts).toBeGreaterThan(0)
    await abandonedContextA.close()

    // A different installation must be able to recover the abandoned,
    // unmanifested server registration. Its authority-signed first manifest
    // selects only its own exact key tuple and atomically prunes the orphan.
    const contextA = await browser.newContext({ baseURL })
    const pageA = await login(contextA, aliceEmail)
    const pageB = await login(contextB, bobEmail)
    await openChat(pageA)
    await openChat(pageB)
    await enableReadReceipts(pageB)
    await expectWasmRuntimeRevalidation(pageA)
    await expectWasmRuntimeRevalidation(pageB)

    const identifiedToBob: string[] = []
    pageA.on('request', (request) => {
      const path = new URL(request.url()).pathname
      if (request.method() === 'POST' && path.includes('/api/chat/users/') && path.endsWith('/messages')) {
        identifiedToBob.push(path)
      }
    })

    await pageA.getByPlaceholder('Username').fill(`${bob}@b.test`)
    await pageA.getByRole('button', { name: 'Start chat' }).click()
    // V1 does not allocate destination media for a message request. Direct
    // attachments become available only after the contact is accepted.
    await expect(pageA.getByTestId('chat-attachment-button')).toBeDisabled()
    const firstIdentified = pageA.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'POST' && path.includes('/api/chat/users/') && path.endsWith('/messages')
    })
    const first = `identified-first-${tag}`
    await send(pageA, first)
    expect((await firstIdentified).ok()).toBe(true)
    await expect(pageB.getByText('1 message request')).toBeVisible({ timeout: 45_000 })
    await pageB.getByRole('button', { name: new RegExp(alice) }).click()
    await expect(bubble(pageB, first)).toBeVisible()
    const acceptRequest = pageB.getByRole('button', { name: 'Accept', exact: true })
    await acceptRequest.click()
    await expect(acceptRequest).toBeHidden({ timeout: 45_000 })

    // The server can distribute signed manifests but cannot promote trust.
    // Both installations independently derive the same full pair/key binding;
    // only an exact face-to-face QR exchange turns the gray shields green.
    await pageA.getByTestId('chat-safety-open').click()
    const safetyA = pageA.getByRole('dialog')
    const qrA = await safetyA.getByTestId('chat-safety-qr').getAttribute('data-value')
    expect(qrA).toMatch(/^kutup:\/\/verify\/chat\/v1\//)
    await pageB.getByTestId('chat-safety-open').click()
    const safetyB = pageB.getByRole('dialog')
    const qrB = await safetyB.getByTestId('chat-safety-qr').getAttribute('data-value')
    expect(qrB).toBe(qrA)
    await safetyB.getByPlaceholder('kutup://verify/chat/v1/…').fill(qrA!)
    await safetyB.getByRole('button', { name: 'Verify exact match' }).click()
    await expect(safetyB.getByText('Verified face to face on this device.')).toBeVisible()
    await pageB.keyboard.press('Escape')
    await safetyA.getByPlaceholder('kutup://verify/chat/v1/…').fill(qrB!)
    await safetyA.getByRole('button', { name: 'Verify exact match' }).click()
    await expect(safetyA.getByText('Verified face to face on this device.')).toBeVisible()
    await pageA.keyboard.press('Escape')

    const sealedReplyResponse = pageB.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'POST'
        && path.includes('/api/chat/anonymous/users/')
        && path.endsWith('/messages')
    })
    const reply = `sealed-reply-${tag}`
    await send(pageB, reply)
    expect((await sealedReplyResponse).ok()).toBe(true)
    // The acceptance/profile update and immediate sealed reply use independent
    // durable paths. Reconciliation must recover either arrival order.
    await syncUntilVisible(pageA, reply)
    await syncUntilReceipt(pageB, reply, 'chat-receipt-delivered')

    const destinationEnvelopes: Array<Record<string, unknown>> = []
    pageB.on('response', (response) => {
      const url = new URL(response.url())
      if (response.request().method() !== 'GET' || url.pathname !== '/api/chat/messages' || !response.ok()) return
      void response.json()
        .then((body: { envelopes?: Array<Record<string, unknown>> }) => {
          destinationEnvelopes.push(...(body.envelopes ?? []))
        })
        .catch(() => {})
    })
    identifiedToBob.length = 0
    const sealedSendResponse = pageA.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'POST'
        && path.includes('/api/chat/anonymous/users/')
        && path.endsWith('/messages')
    })
    const sealed = `sealed-second-${tag}`
    await send(pageA, sealed)
    expect((await sealedSendResponse).ok()).toBe(true)
    await pageB.getByRole('button', { name: 'Sync messages' }).click()
    await expect.poll(
      () => destinationEnvelopes.some((envelope) => envelope.sealedSender === true),
      { timeout: 45_000 },
    ).toBe(true)
    const destinationEnvelope = destinationEnvelopes.find((envelope) => envelope.sealedSender === true)
    expect(destinationEnvelope).not.toHaveProperty('sender')
    expect(destinationEnvelope?.senderDeviceId).toBe(0)
    await expect(bubble(pageB, sealed)).toBeVisible({ timeout: 45_000 })
    await syncUntilReceipt(pageA, sealed, 'chat-receipt-read')
    const quotedReply = `sealed-quoted-reply-${tag}`
    await replyTo(pageB, sealed, quotedReply)
    await syncUntilVisible(pageA, quotedReply)
    const quotedMessage = pageA.getByTestId('chat-message').filter({ hasText: quotedReply })
    await expect(quotedMessage.getByTestId('chat-reply-context')).toContainText(sealed)

    await reactTo(pageB, sealed, '👍')
    await syncUntilReaction(pageA, sealed, '👍', 1)
    await reactionTarget(pageA, sealed)
      .getByTestId('chat-reaction-aggregate')
      .click()
    await syncUntilReaction(pageB, sealed, '👍', 2)
    await reactionTarget(pageB, sealed)
      .getByTestId('chat-reaction-aggregate')
      .click()
    await syncUntilReaction(pageA, sealed, '👍', 1)
    const editedSealed = `edited-sealed-${tag}`
    await editMessage(pageA, sealed, editedSealed)
    await syncUntilVisible(pageB, editedSealed)
    await expect(reactionTarget(pageB, editedSealed).getByTestId('chat-message-edited')).toBeVisible()
    await deleteMessage(pageA, editedSealed)
    await syncUntilDeleted(pageB)
    expect(identifiedToBob).toEqual([])

    const directAttachment = `direct-attachment-${tag}.txt`
    const directAttachmentBody = `federated encrypted attachment ${tag}`
    await expect(pageA.getByTestId('chat-attachment-button')).toBeEnabled({ timeout: 45_000 })
    await sendAttachment(pageA, directAttachment, directAttachmentBody)
    await syncUntilAttachment(pageB, directAttachment)
    expect(await downloadAttachment(pageB, directAttachment)).toBe(directAttachmentBody)

    await pageB.getByTestId('chat-storage-button').click()
    await expect(pageB.getByTestId('chat-storage-summary')).toBeVisible({ timeout: 45_000 })
    await expect(pageB.getByText('Chat media', { exact: true })).toBeVisible()
    pageB.once('dialog', dialog => void dialog.accept())
    await pageB.getByRole('button', { name: /Clear stored Chat media/ }).click()
    await expect(pageB.getByText('No categorized Chat attachments yet.')).toBeVisible({
      timeout: 45_000,
    })
    await pageB.keyboard.press('Escape')
    await pageB.getByRole('button', { name: `Download ${directAttachment}` }).click()
    await expect(pageB.locator('[data-sonner-toast][data-type="error"]')).toContainText(
      'Encrypted attachment download failed',
      { timeout: 45_000 },
    )

    const noteAttachment = `note-attachment-${tag}.txt`
    const noteAttachmentBody = `encrypted note to self attachment ${tag}`
    await pageA.getByText('Note to Self', { exact: true }).first().click()
    await expect(pageA.getByTestId('chat-attachment-button')).toBeEnabled()
    await sendAttachment(pageA, noteAttachment, noteAttachmentBody, false)
    await syncUntilAttachment(pageA, noteAttachment)
    expect(await downloadAttachment(pageA, noteAttachment)).toBe(noteAttachmentBody)

    await pageA.getByRole('button', { name: new RegExp(bob) }).click()

    // Blocking publishes the new profile key/capability before returning.
    // Alice's stolen/stale capability receives the uniform 404 and the
    // established conversation must not attempt the identified endpoint.
    await pageB.getByRole('button', { name: 'Block', exact: true }).click()
    await expect(pageB.getByRole('button', { name: 'Unblock', exact: true })).toBeVisible({
      timeout: 45_000,
    })
    identifiedToBob.length = 0
    const rejectedAnonymous = pageA.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'POST'
        && path.includes('/api/chat/anonymous/users/')
        && (path.endsWith('/keys') || path.endsWith('/messages'))
        && response.status() === 404
    })
    await send(pageA, `rejected-stale-capability-${tag}`)
    await rejectedAnonymous
    await pageA.waitForTimeout(1_000)
    expect(identifiedToBob).toEqual([])
    await expect(bubble(pageB, `rejected-stale-capability-${tag}`)).toHaveCount(0)

    expectNoPageErrors(pageA, pageB)
    await contextA.close()
    await contextB.close()
  })

  test('manages a federated MLS group and exchanges anonymous durable messages', async ({ browser, baseURL }) => {
    test.slow()
    if (!baseURL || !SECONDARY) throw new Error('two-server base URLs are required')
    const contextA = await browser.newContext({ baseURL })
    const contextB = await browser.newContext({ baseURL: SECONDARY })
    const contextC = await browser.newContext({ baseURL })
    const contextD = await browser.newContext({ baseURL: SECONDARY })
    const tag = Date.now() % 1_000_000
    const alice = `mlsalice${tag}`
    const bob = `mlsbob${tag}`
    const charlie = `mlscarol${tag}`
    const dave = `mlsdave${tag}`
    const aliceEmail = `${alice}@example.test`
    const bobEmail = `${bob}@example.test`
    const charlieEmail = `${charlie}@example.test`
    const daveEmail = `${dave}@example.test`

    await register(contextA, aliceEmail, alice)
    await register(contextB, bobEmail, bob)
    await register(contextC, charlieEmail, charlie)
    await register(contextD, daveEmail, dave)
    const pageA = await login(contextA, aliceEmail)
    const pageB = await login(contextB, bobEmail)
    const pageC = await login(contextC, charlieEmail)
    const pageD = await login(contextD, daveEmail)
    await openChat(pageA)
    await openChat(pageB)
    await enableReadReceipts(pageB)
    await openChat(pageC)
    await openChat(pageD)

    const genesisResponse = pageA.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'POST'
        && path === '/api/chat/mls/conversations'
    })
    const identifiedPackages = pageA.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'POST'
        && path === '/api/chat/mls/key-packages/identified'
    })
    const membershipCommit = pageA.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'POST'
        && path === '/api/chat/mls/control/blocks'
    })
    const createGroup = pageA.getByTestId('chat-create-group')
    await expect(createGroup).toBeVisible()
    await createGroup.click()
    await pageA.getByTestId('chat-group-initial-member').fill(`${bob}@b.test`)
    await pageA.getByTestId('chat-group-create-submit').click()
    const genesis = await genesisResponse
    expect(genesis.ok()).toBe(true)
    const { conversationId } = await genesis.json() as { conversationId: string }
    const genesisRequest = genesis.request().postDataJSON() as {
      genesis: {
        authoritySet: {
          authorities: Array<{ domain: string; keyId: string; publicKey: string }>
        }
        ownerSet: {
          owners: Array<{ ownerId: string; publicKey: string }>
        }
      }
    }
    expect(conversationId).toMatch(/^[0-9a-f-]{36}$/)
    const identifiedPackageResponse = await identifiedPackages
    expect(identifiedPackageResponse.ok()).toBe(true)
    const identifiedPackageRequest = identifiedPackageResponse.request().postDataJSON()
    expect((await membershipCommit).ok()).toBe(true)
    await expect(pageA.getByTestId(`chat-group-${conversationId}`)).toBeVisible({ timeout: 90_000 })
    await expect(pageA.getByTestId('chat-group-delivery-readiness')).toContainText(
      `Waiting for ${bob}@b.test to accept`,
    )
    await expect(pageA.getByRole('button', { name: 'Send', exact: true })).toBeDisabled()

    // No manual Sync action: the destination server sends only a generic
    // DrainMailbox WebSocket hint after committing the federated Welcome.
    await expect(pageB.getByTestId('chat-group-invitations')).toBeVisible({ timeout: 90_000 })
    const invitationAcceptance = pageB.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'POST'
        && path === '/api/chat/mls/invitations'
    })
    await pageB.getByTestId('chat-group-accept').click()
    const invitationAcceptanceResponse = await invitationAcceptance
    expect(invitationAcceptanceResponse.ok()).toBe(true)
    await expect(pageB.getByTestId(`chat-group-${conversationId}`)).toBeVisible({ timeout: 90_000 })
    await expect(pageA.getByTestId('chat-group-delivery-readiness')).toHaveCount(0, {
      timeout: 90_000,
    })

    // The member-visible security panel must show exact group owner
    // credentials and group-pinned authority keys, then independently verify
    // the complete federation identity/policy history before showing live
    // policy and identity fingerprints. Assertions compare the UI against the
    // signed genesis and actual two-server policy responses, not fixtures.
    const policyResponseFor = (domain: string) => pageA.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'GET'
        && path === `/api/chat/mls/domains/${domain}/policy`
        && response.ok()
    })
    const aPolicyResponse = policyResponseFor('a.test')
    const bPolicyResponse = policyResponseFor('b.test')
    await pageA.getByTestId('chat-group-members').click()
    const [aPolicyHistory, bPolicyHistory] = await Promise.all([
      aPolicyResponse.then(response => response.json()),
      bPolicyResponse.then(response => response.json()),
    ]) as Array<{
      identities: Array<{
        sequence: number
        key: { keyId: string; publicKey: string }
      }>
      policies: Array<{
        sequence: number
        federationIdentityGeneration: number
        payload: string
      }>
    }>
    const assertExactAuthoritySecurity = async (
      domain: string,
      history: typeof aPolicyHistory,
    ) => {
      const envelope = history.policies.at(-1)
      expect(envelope).toBeDefined()
      const policy = JSON.parse(
        Buffer.from(envelope!.payload, 'base64').toString('utf8'),
      ) as {
        controlSigningKeyId: string
        controlSigningPublicKey: string
        maximumGroupMembers: number
      }
      const identity = history.identities.find(
        candidate => candidate.sequence === envelope!.federationIdentityGeneration,
      )
      expect(identity).toBeDefined()
      const genesisAuthority = genesisRequest.genesis.authoritySet.authorities.find(
        candidate => candidate.domain === domain,
      )
      expect(genesisAuthority).toBeDefined()
      expect(policy.controlSigningKeyId).toBe(genesisAuthority!.keyId)
      expect(policy.controlSigningPublicKey).toBe(genesisAuthority!.publicKey)
      await expect(
        pageA.getByTestId(`chat-group-authority-policy-match-${domain}`),
      ).toBeVisible({ timeout: 90_000 })
      await expect(
        pageA.getByTestId(`chat-group-authority-pin-${domain}`),
      ).toContainText(genesisAuthority!.keyId)
      const exactPolicy = pageA.getByTestId(`chat-group-authority-policy-${domain}`)
      await exactPolicy.getByText('Exact authenticated service policy').click()
      await expect(
        pageA.getByTestId(`chat-group-authority-policy-fingerprint-${domain}`),
      ).toContainText(policy.controlSigningKeyId)
      await expect(
        pageA.getByTestId(`chat-group-authority-identity-fingerprint-${domain}`),
      ).toContainText(identity!.key.keyId)
      await expect(
        pageA.getByTestId(`chat-group-authority-policy-sequence-${domain}`),
      ).toContainText(String(envelope!.sequence))
      await expect(
        pageA.getByTestId(`chat-group-authority-${domain}`),
      ).toContainText(String(policy.maximumGroupMembers))
      await exactPolicy.getByText('Exact authenticated service policy').click()
    }
    const genesisOwner = genesisRequest.genesis.ownerSet.owners[0]
    expect(genesisOwner).toBeDefined()
    await expect(
      pageA.getByTestId(`chat-group-owner-fingerprint-${alice}@a.test`),
    ).toContainText(genesisOwner.ownerId)
    await expect(
      pageA.getByTestId(`chat-group-owner-credential-${alice}@a.test`),
    ).toContainText(genesisOwner.publicKey)
    await assertExactAuthoritySecurity('a.test', aPolicyHistory)
    await assertExactAuthoritySecurity('b.test', bPolicyHistory)
    await pageA.keyboard.press('Escape')

    // An active member may claim only its own packages for linked-device leaf
    // synchronization. Membership alone must not authorize cross-account
    // first-contact claims, which protects other users from package exhaustion.
    const bobAuthorization = await invitationAcceptanceResponse.request().headerValue('authorization')
    expect(bobAuthorization).toMatch(/^Bearer /)
    const packageClaimStatuses = await pageB.evaluate(
      async ({ authorization, selfRequest, crossAccountRecipient }) => {
        const claim = async (request: Record<string, unknown>) => {
          const response = await fetch('/api/chat/mls/key-packages/identified', {
            method: 'POST',
            headers: {
              Authorization: authorization!,
              'Content-Type': 'application/json',
            },
            body: JSON.stringify(request),
          })
          return response.status
        }
        const crossAccountRequest = {
          ...selfRequest,
          recipient: crossAccountRecipient,
        }
        return {
          self: await claim(selfRequest),
          crossAccount: await claim(crossAccountRequest),
        }
      },
      {
        authorization: bobAuthorization,
        selfRequest: identifiedPackageRequest,
        crossAccountRecipient: { username: alice, server: 'a.test' },
      },
    )
    expect(packageClaimStatuses.self).toBe(200)
    expect(packageClaimStatuses.crossAccount).toBe(403)

    // Routine administrator changes use the same encrypted roster transition,
    // but preserve member count and routing domains and require no owner vote.
    const administratorCommit = pageA.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'POST'
        && path === '/api/chat/mls/control/blocks'
    })
    await pageA.getByTestId('chat-group-members').click()
    const bobOnAlice = pageA.getByTestId(`chat-group-member-${bob}@b.test`)
    await bobOnAlice.getByRole('button', {
      name: `Make administrator ${bob}@b.test`,
    }).click()
    expect((await requireResponseOrUiError(pageA, administratorCommit)).ok()).toBe(true)
    await expect(bobOnAlice.getByText('Administrator', { exact: true })).toBeVisible({ timeout: 90_000 })
    await pageA.keyboard.press('Escape')

    await pageB.getByTestId('chat-group-members').click()
    await expect(
      pageB.getByTestId(`chat-group-member-${bob}@b.test`)
        .getByText('Administrator', { exact: true }),
    ).toBeVisible({ timeout: 90_000 })
    await pageB.keyboard.press('Escape')

    const administratorAddCommit = pageB.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'POST'
        && path === '/api/chat/mls/control/blocks'
    })
    await pageB.getByTestId('chat-group-add-member').click()
    await pageB.getByLabel('Group member address').fill(`${charlie}@a.test`)
    await pageB.getByRole('button', { name: 'Invite member' }).click()
    expect((await requireResponseOrUiError(pageB, administratorAddCommit)).ok()).toBe(true)
    await expect(pageC.getByTestId('chat-group-invitations')).toBeVisible({ timeout: 90_000 })
    await pageC.getByTestId('chat-group-accept').click()
    await expect(pageC.getByTestId(`chat-group-${conversationId}`)).toBeVisible({ timeout: 90_000 })
    // Charlie was invited by Bob on b.test, so Alice's a.test server does not
    // receive the plaintext origin-scoped receipt. Alice unlocks only after
    // processing Charlie's MLS-encrypted, exact-join-epoch acceptance.
    await expect(pageA.getByTestId('chat-group-delivery-readiness')).toHaveCount(0, {
      timeout: 90_000,
    })

    await pageA.getByTestId('chat-group-members').click()
    await expect(
      pageA.getByTestId(`chat-group-member-${charlie}@a.test`),
    ).toBeVisible({ timeout: 90_000 })
    await pageA.keyboard.press('Escape')
    await expect(
      pageA.getByRole('heading', { name: 'MLS group members' }),
    ).toBeHidden()

    // A rejected cross-server Welcome produces durable, federation-authenticated
    // advisory feedback. It cannot mutate the MLS roster: Alice must see the
    // exact member warning and manually commit the cryptographic removal.
    const rejectedMemberAddCommit = pageA.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'POST'
        && path === '/api/chat/mls/control/blocks'
    })
    await pageA.getByTestId('chat-group-add-member').click()
    await pageA.getByLabel('Group member address').fill(`${dave}@b.test`)
    await pageA.getByRole('button', { name: 'Invite member' }).click()
    const rejectedMemberAddResponse =
      await requireResponseOrUiError(pageA, rejectedMemberAddCommit)
    expect(rejectedMemberAddResponse.ok()).toBe(true)
    const aliceAuthorization =
      await rejectedMemberAddResponse.request().headerValue('authorization')
    expect(aliceAuthorization).toMatch(/^Bearer /)
    await expect(pageD.getByTestId('chat-group-invitations')).toBeVisible({ timeout: 90_000 })
    const invitationRejection = pageD.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'POST'
        && path === '/api/chat/mls/invitations'
    })
    await pageD.getByRole('button', { name: 'Reject' }).click()
    expect((await invitationRejection).ok()).toBe(true)
    await expect(pageD.getByTestId('chat-group-invitations')).toHaveCount(0)

    await expect.poll(
      () => pageA.evaluate(async ({ authorization, groupId, member }) => {
        const response = await fetch('/api/chat/mls/invitation-feedback', {
          headers: { Authorization: authorization! },
        })
        if (!response.ok) return false
        const feedback = await response.json() as Array<{
          conversationId: string
          member: { username: string; server?: string }
          decision: string
        }>
        return feedback.some(entry =>
          entry.conversationId === groupId
          && `${entry.member.username}@${entry.member.server}` === member
          && entry.decision === 'rejected')
      }, {
        authorization: aliceAuthorization,
        groupId: conversationId,
        member: `${dave}@b.test`,
      }),
      { timeout: 90_000 },
    ).toBe(true)

    await pageA.reload()
    await expect(pageA.getByRole('heading', { name: 'Messages' })).toBeVisible({ timeout: 90_000 })
    await pageA.getByTestId(`chat-group-${conversationId}`).click()
    await pageA.getByTestId('chat-group-members').click()
    await expect(
      pageA.getByTestId(`chat-group-invitation-feedback-${dave}@b.test`),
    ).toContainText('Rejected the invitation', { timeout: 90_000 })
    const rejectedMemberRemoveCommit = pageA.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'POST'
        && path === '/api/chat/mls/control/blocks'
    })
    await pageA.getByRole('button', {
      name: `Remove ${dave}@b.test from group`,
    }).click()
    expect((await requireResponseOrUiError(pageA, rejectedMemberRemoveCommit)).ok()).toBe(true)
    await expect(
      pageA.getByTestId(`chat-group-member-${dave}@b.test`),
    ).toHaveCount(0, { timeout: 90_000 })
    await pageA.keyboard.press('Escape')

    // Promote Bob while the current owner set is Alice-only (q=1), then prove
    // the resulting two-owner set (q=2) cannot remove Bob until his exact
    // encrypted manual approval returns. Both clients restart with the
    // partially approved transition/request still durable.
    const promoteOwnerCommit = pageA.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'POST'
        && path === '/api/chat/mls/control/blocks'
    })
    await pageA.getByTestId('chat-group-members').click()
    await pageA.getByTestId(`chat-group-owner-${bob}@b.test`).click()
    expect((await requireResponseOrUiError(pageA, promoteOwnerCommit)).ok()).toBe(true)
    await expect(
      pageA.getByTestId(`chat-group-member-owner-${bob}@b.test`),
    ).toBeVisible({ timeout: 90_000 })
    await pageA.keyboard.press('Escape')

    await pageB.getByTestId('chat-group-members').click()
    await expect(
      pageB.getByTestId(`chat-group-member-owner-${bob}@b.test`),
    ).toBeVisible({ timeout: 90_000 })
    await pageB.keyboard.press('Escape')

    let ownerRemovalControlSubmitted = false
    let awaitingOwnerRemovalApproval = true
    pageA.on('request', (request) => {
      if (
        awaitingOwnerRemovalApproval
        && request.method() === 'POST'
        && new URL(request.url()).pathname === '/api/chat/mls/control/blocks'
      ) ownerRemovalControlSubmitted = true
    })
    const ownerApprovalRequest = pageA.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'POST'
        && path === '/api/chat/mls/anonymous/messages'
    })
    await pageA.getByTestId('chat-group-members').click()
    await pageA.getByTestId(`chat-group-owner-${bob}@b.test`).click()
    expect((await requireResponseOrUiError(pageA, ownerApprovalRequest)).ok()).toBe(true)
    await pageA.waitForTimeout(1_000)
    expect(ownerRemovalControlSubmitted).toBe(false)

    await pageA.reload()
    await expect(pageA.getByRole('heading', { name: 'Messages' })).toBeVisible({ timeout: 90_000 })
    await pageA.getByTestId(`chat-group-${conversationId}`).click()

    await pageB.getByTestId('chat-group-members').click()
    await expect(pageB.getByTestId('chat-group-owner-approval')).toBeVisible({ timeout: 90_000 })
    await pageB.reload()
    await expect(pageB.getByRole('heading', { name: 'Messages' })).toBeVisible({ timeout: 90_000 })
    await pageB.getByTestId(`chat-group-${conversationId}`).click()
    await pageB.getByTestId('chat-group-members').click()
    await expect(pageB.getByTestId('chat-group-owner-approval')).toBeVisible({ timeout: 90_000 })

    const ownerApprovalResponse = pageB.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'POST'
        && path === '/api/chat/mls/anonymous/messages'
    })
    const removeOwnerCommit = pageA.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'POST'
        && path === '/api/chat/mls/control/blocks'
    })
    await pageB.getByTestId('chat-group-owner-approve').click()
    expect((await requireResponseOrUiError(pageB, ownerApprovalResponse)).ok()).toBe(true)
    awaitingOwnerRemovalApproval = false
    expect((await requireResponseOrUiError(pageA, removeOwnerCommit)).ok()).toBe(true)
    await pageB.keyboard.press('Escape')

    await pageA.getByTestId('chat-group-members').click()
    await expect(
      pageA.getByTestId(`chat-group-member-owner-${bob}@b.test`),
    ).toHaveCount(0, { timeout: 90_000 })
    await closeGroupMembers(pageA)

    // The owner changes ordering authorities through one owner-approved MLS
    // Commit and joint old/new quorums. Removing b.test still delivers the
    // exact Commit to Bob because participant routing is independent from the
    // ordering set.
    const removeAuthorityCommit = pageA.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'POST'
        && path === '/api/chat/mls/control/blocks'
    })
    await pageA.getByTestId('chat-group-members').click()
    await pageA.getByTestId('chat-group-authority-domains').fill('a.test')
    await pageA.getByTestId('chat-group-save-authorities').click()
    expect((await requireResponseOrUiError(pageA, removeAuthorityCommit)).ok()).toBe(true)
    await expect(pageA.getByTestId('chat-group-authority-a.test')).toBeVisible({ timeout: 90_000 })
    await expect(pageA.getByTestId('chat-group-authority-b.test')).toHaveCount(0)
    await closeGroupMembers(pageA)

    await pageB.getByTestId('chat-group-members').click()
    await expect(pageB.getByTestId('chat-group-authority-a.test')).toBeVisible({ timeout: 90_000 })
    await expect(pageB.getByTestId('chat-group-authority-b.test')).toHaveCount(0)
    await closeGroupMembers(pageB)

    // Adding b.test back exercises exact history bootstrap before b.test may
    // contribute its new-set vote. Both participant clients then pin sequence 3.
    const addAuthorityCommit = pageA.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'POST'
        && path === '/api/chat/mls/control/blocks'
    })
    await pageA.getByTestId('chat-group-members').click()
    await pageA.getByTestId('chat-group-authority-domains').fill('a.test, b.test')
    await pageA.getByTestId('chat-group-save-authorities').click()
    expect((await requireResponseOrUiError(pageA, addAuthorityCommit)).ok()).toBe(true)
    await expect(pageA.getByTestId('chat-group-authority-b.test')).toBeVisible({ timeout: 90_000 })
    await closeGroupMembers(pageA)

    await pageB.getByTestId('chat-group-members').click()
    await expect(pageB.getByTestId('chat-group-authority-b.test')).toBeVisible({ timeout: 90_000 })
    await closeGroupMembers(pageB)

    const destinationMailbox: Array<Record<string, unknown>> = []
    pageB.on('response', (response) => {
      const url = new URL(response.url())
      if (
        response.request().method() !== 'GET'
        || !/^\/api\/chat\/mls\/messages\/\d+$/.test(url.pathname)
        || !response.ok()
      ) return
      void response.json()
        .then((body: { envelopes?: Array<Record<string, unknown>> }) => {
          destinationMailbox.push(...(body.envelopes ?? []))
        })
        .catch(() => {})
    })

    await expect(pageA.locator('[data-sonner-toast][data-type="error"]')).toHaveCount(0)

    const sentToBob = pageA.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'POST'
        && path === '/api/chat/mls/anonymous/messages'
    })
    const fromAlice = `mls-from-alice-${tag}`
    await send(pageA, fromAlice)
    const firstAnonymousResponse = await requireResponseOrUiError(pageA, sentToBob)
    expect(firstAnonymousResponse.ok()).toBe(true)
    const firstAnonymousSubmission =
      firstAnonymousResponse.request().postDataJSON() as Record<string, unknown>
    await expect(bubble(pageB, fromAlice)).toBeVisible({ timeout: 90_000 })
    await syncUntilReceipt(pageA, fromAlice, 'chat-receipt-read')
    await expect.poll(
      () => destinationMailbox.some(envelope => envelope.deliveryKind === 'anonymous'),
      { timeout: 45_000 },
    ).toBe(true)
    const anonymous = destinationMailbox.find(envelope => envelope.deliveryKind === 'anonymous')
    expect(anonymous).not.toHaveProperty('conversationId')
    expect(anonymous).not.toHaveProperty('incarnation')

    // Exact anonymous retries reuse the same signed origin sequence and do not
    // create another destination mailbox row. Reusing the UUID for different
    // ciphertext is an origin-side conflict before federation.
    const replay = await pageA.evaluate(async (submission) => {
      const response = await fetch('/api/chat/mls/anonymous/messages', {
        method: 'POST',
        credentials: 'omit',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(submission),
      })
      return { status: response.status, body: await response.json() }
    }, firstAnonymousSubmission)
    expect(replay).toMatchObject({ status: 200, body: { accepted: true } })
    await pageB.waitForTimeout(1_000)
    await expect(bubble(pageB, fromAlice)).toHaveCount(1)

    const conflictingReplay = await pageA.evaluate(async (submission) => {
      const changed = structuredClone(submission) as {
        envelopes: Array<{ ciphertext: string }>
      }
      const ciphertext = changed.envelopes[0].ciphertext
      changed.envelopes[0].ciphertext =
        `${ciphertext.startsWith('A') ? 'B' : 'A'}${ciphertext.slice(1)}`
      const response = await fetch('/api/chat/mls/anonymous/messages', {
        method: 'POST',
        credentials: 'omit',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(changed),
      })
      return response.status
    }, firstAnonymousSubmission)
    expect(conflictingReplay).toBe(409)

    // Unknown recipients and known recipients with an invalid capability are
    // deliberately indistinguishable at the same-origin anonymous boundary.
    const enumerationResponses = await pageA.evaluate(
      async ({ knownRecipient, unknownUsername }) => {
        const unknownRecipient = structuredClone(knownRecipient) as { username: string }
        unknownRecipient.username = unknownUsername
        const claim = async (recipient: unknown) => {
          const response = await fetch('/api/chat/mls/anonymous/key-packages', {
            method: 'POST',
            credentials: 'omit',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              protocolVersion: 1,
              recipient,
              capability: 'AAAAAAAAAAAAAAAAAAAAAA==',
            }),
          })
          return { status: response.status, body: await response.text() }
        }
        return Promise.all([claim(knownRecipient), claim(unknownRecipient)])
      },
      {
        knownRecipient: firstAnonymousSubmission.recipient,
        unknownUsername: `mlsunknown${tag}`,
      },
    )
    expect(enumerationResponses[0].status).toBe(404)
    expect(enumerationResponses[1].status).toBe(404)
    expect(enumerationResponses[0].body).toBe(enumerationResponses[1].body)

    const sentToAlice = pageB.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'POST'
        && path === '/api/chat/mls/anonymous/messages'
    })
    const fromBob = `mls-from-bob-${tag}`
    await send(pageB, fromBob)
    expect((await requireResponseOrUiError(pageB, sentToAlice)).ok()).toBe(true)
    await expect(bubble(pageA, fromBob)).toBeVisible({ timeout: 90_000 })

    await reactTo(pageB, fromAlice, '❤️')
    await syncUntilReaction(pageA, fromAlice, '❤️', 1)
    await reactionTarget(pageA, fromAlice)
      .getByTestId('chat-reaction-aggregate')
      .click()
    await syncUntilReaction(pageB, fromAlice, '❤️', 2)

    const groupAttachment = `mls-attachment-${tag}.txt`
    const groupAttachmentBody = `MLS encrypted attachment ${tag}`
    await sendAttachment(pageA, groupAttachment, groupAttachmentBody)
    await syncUntilAttachment(pageB, groupAttachment)
    expect(await downloadAttachment(pageB, groupAttachment)).toBe(groupAttachmentBody)

    await pageB.reload()
    await expect(pageB.getByRole('heading', { name: 'Messages' })).toBeVisible({ timeout: 90_000 })
    await expect(pageB.getByTestId(`chat-group-${conversationId}`)).toBeVisible({ timeout: 90_000 })
    await expect(bubble(pageB, fromAlice)).toBeVisible({ timeout: 90_000 })
    await expect(bubble(pageB, fromBob)).toBeVisible({ timeout: 90_000 })
    const editedFromBob = `mls-edited-from-bob-${tag}`
    await editMessage(pageB, fromBob, editedFromBob)
    await syncUntilVisible(pageA, editedFromBob)
    await expect(reactionTarget(pageA, editedFromBob).getByTestId('chat-message-edited')).toBeVisible()
    await pageB.getByTestId('chat-storage-button').click()
    await expect(pageB.getByTestId('chat-storage-summary')).toBeVisible({ timeout: 45_000 })
    await expect(pageB.getByRole('button', {
      name: `Clear stored Chat media for Group ${conversationId.slice(0, 8)}`,
    })).toBeVisible()
    await pageB.keyboard.press('Escape')
    expect(await downloadAttachment(pageB, groupAttachment)).toBe(groupAttachmentBody)

    // A fresh Alice install owns independent MLS credentials and leaf secrets.
    // The existing Alice device commits a manifest-bound DeviceSync Welcome;
    // the new device verifies the complete signed control history, joins
    // without an invitation decision, and survives a browser restart.
    const { context: contextA2, page: pageA2 } = await cloneAuthenticatedInstall(
      browser,
      contextA,
      pageA,
    )
    await openChat(pageA2)
    const bobCapabilityEpochs: number[] = []
    pageB.on('response', (response) => {
      const path = new URL(response.url()).pathname
      if (
        !response.ok()
        || response.request().method() !== 'PUT'
        || path !== '/api/chat/mls/delivery-capability'
      ) return
      try {
        const publication = response.request().postDataJSON() as {
          conversationId?: unknown
          epoch?: unknown
        }
        if (
          publication.conversationId === conversationId
          && typeof publication.epoch === 'number'
          && Number.isSafeInteger(publication.epoch)
        ) {
          bobCapabilityEpochs.push(publication.epoch)
        }
      } catch {
        // A malformed publication is independently rejected by the server.
      }
    })
    const linkedDeviceCommit = pageA.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'POST'
        && path === '/api/chat/mls/control/blocks'
    })
    await pageA.reload()
    await expect(pageA.getByRole('heading', { name: 'Messages' })).toBeVisible({ timeout: 90_000 })
    const linkedDeviceCommitResponse =
      await requireResponseOrUiError(pageA, linkedDeviceCommit)
    expect(linkedDeviceCommitResponse.ok()).toBe(true)
    const linkedDeviceCommitBody =
      await linkedDeviceCommitResponse.json() as { epoch?: unknown }
    expect(linkedDeviceCommitBody.epoch).toEqual(expect.any(Number))
    const linkedDeviceEpoch = linkedDeviceCommitBody.epoch as number
    await expect(pageA2.getByTestId(`chat-group-${conversationId}`)).toBeVisible({
      timeout: 90_000,
    })
    await pageA2.getByTestId('chat-storage-button').click()
    await expect(pageA2.getByTestId('chat-storage-summary')).toBeVisible({ timeout: 45_000 })
    await expect(pageA2.getByRole('button', {
      name: `Clear stored Chat media for Group ${conversationId.slice(0, 8)}`,
    })).toBeVisible()
    await pageA2.keyboard.press('Escape')
    await expect.poll(
      () => bobCapabilityEpochs.includes(linkedDeviceEpoch),
      { timeout: 90_000 },
    ).toBe(true)

    // The new epoch verifier atomically replaces the old one. A copied
    // capability plus opaque envelope from epoch N must become the same
    // uniform unavailable response used for an unknown recipient.
    const staleCapability = await pageA.evaluate(async (submission) => {
      const stolen = structuredClone(submission) as Record<string, unknown>
      stolen.sendId = crypto.randomUUID()
      const response = await fetch('/api/chat/mls/anonymous/messages', {
        method: 'POST',
        credentials: 'omit',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(stolen),
      })
      return { status: response.status, body: await response.text() }
    }, firstAnonymousSubmission)
    expect(staleCapability).toEqual(enumerationResponses[0])

    await pageA2.getByTestId(`chat-group-${conversationId}`).click()
    const linkedSendResponse = pageA2.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'POST'
        && path === '/api/chat/mls/anonymous/messages'
    })
    const fromAliceLinked = `mls-from-alice-linked-${tag}`
    await send(pageA2, fromAliceLinked)
    expect((await requireResponseOrUiError(pageA2, linkedSendResponse)).ok()).toBe(true)
    await expect(bubble(pageB, fromAliceLinked)).toBeVisible({ timeout: 90_000 })

    const toAliceLinkedResponse = pageB.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'POST'
        && path === '/api/chat/mls/anonymous/messages'
    })
    const toAliceLinked = `mls-to-alice-linked-${tag}`
    await send(pageB, toAliceLinked)
    expect((await requireResponseOrUiError(pageB, toAliceLinkedResponse)).ok()).toBe(true)
    await expect(bubble(pageA2, toAliceLinked)).toBeVisible({ timeout: 90_000 })
    await pageA2.reload()
    await expect(pageA2.getByRole('heading', { name: 'Messages' })).toBeVisible({ timeout: 90_000 })
    await pageA2.getByTestId(`chat-group-${conversationId}`).click()
    await expect(bubble(pageA2, fromAliceLinked)).toBeVisible({ timeout: 90_000 })
    await expect(bubble(pageA2, toAliceLinked)).toBeVisible({ timeout: 90_000 })

    // Re-promoting the previously demoted owner reuses the exact durable
    // group-scoped candidate key. The resulting q=2 owner set first proves
    // restart-safe incarnation recovery without an ordering vote, then closes
    // the recovered incarnation through the ordinary control quorum.
    const repromoteOwnerCommit = pageA.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'POST'
        && path === '/api/chat/mls/control/blocks'
    })
    await pageA.getByTestId('chat-group-members').click()
    await pageA.getByTestId(`chat-group-owner-${bob}@b.test`).click()
    expect((await requireResponseOrUiError(pageA, repromoteOwnerCommit)).ok()).toBe(true)
    await expect(
      pageA.getByTestId(`chat-group-member-owner-${bob}@b.test`),
    ).toBeVisible({ timeout: 90_000 })
    await pageA.keyboard.press('Escape')

    await pageB.getByTestId('chat-group-members').click()
    await expect(
      pageB.getByTestId(`chat-group-member-owner-${bob}@b.test`),
    ).toBeVisible({ timeout: 90_000 })
    await pageB.keyboard.press('Escape')

    // Private group policy uses the same exact owner-only approval exchange.
    // The policy value stays in MLS; ordering sees only an unchanged-roster
    // transition. Restart both owners before approval to prove durable resume.
    let senderPolicyControlSubmitted = false
    let awaitingSenderPolicyApproval = true
    pageA.on('request', (request) => {
      if (
        awaitingSenderPolicyApproval
        && request.method() === 'POST'
        && new URL(request.url()).pathname === '/api/chat/mls/control/blocks'
      ) senderPolicyControlSubmitted = true
    })
    const senderPolicyApprovalRequest = pageA.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'POST'
        && path === '/api/chat/mls/anonymous/messages'
    })
    await pageA.getByTestId('chat-group-members').click()
    await pageA.getByTestId('chat-group-senders-administrators').click()
    expect((await requireResponseOrUiError(pageA, senderPolicyApprovalRequest)).ok()).toBe(true)
    await pageA.waitForTimeout(1_000)
    expect(senderPolicyControlSubmitted).toBe(false)
    await pageA.reload()
    await expect(pageA.getByRole('heading', { name: 'Messages' })).toBeVisible({ timeout: 90_000 })
    await pageA.getByTestId(`chat-group-${conversationId}`).click()

    const senderPolicyApprovalPrompt = pageB.getByText('Approve who may send messages?')
    if (!(await senderPolicyApprovalPrompt.isVisible())) {
      await pageB.getByTestId('chat-group-members').click()
    }
    await expect(senderPolicyApprovalPrompt).toBeVisible({ timeout: 90_000 })
    await pageB.reload()
    await expect(pageB.getByRole('heading', { name: 'Messages' })).toBeVisible({ timeout: 90_000 })
    await pageB.getByTestId(`chat-group-${conversationId}`).click()
    await pageB.getByTestId('chat-group-members').click()
    await expect(pageB.getByText('Approve who may send messages?')).toBeVisible({ timeout: 90_000 })

    const senderPolicyApprovalResponse = pageB.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'POST'
        && path === '/api/chat/mls/anonymous/messages'
    })
    const senderPolicyCommit = pageA.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'POST'
        && path === '/api/chat/mls/control/blocks'
    })
    await pageB.getByTestId('chat-group-owner-approve').click()
    expect((await requireResponseOrUiError(pageB, senderPolicyApprovalResponse)).ok()).toBe(true)
    awaitingSenderPolicyApproval = false
    expect((await requireResponseOrUiError(pageA, senderPolicyCommit)).ok()).toBe(true)
    await pageB.keyboard.press('Escape')

    await pageA.getByTestId('chat-group-members').click()
    await expect(pageA.getByTestId('chat-group-senders-administrators')).toBeDisabled({
      timeout: 90_000,
    })
    await pageA.keyboard.press('Escape')
    // The orderer acknowledgement only proves that Alice finalized the block.
    // Wait until the remote owner has independently applied that epoch and
    // published its epoch-bound delivery capability before sending the next
    // owner-approval request.
    await pageB.getByTestId('chat-group-members').click()
    await expect(pageB.getByTestId('chat-group-senders-administrators')).toBeDisabled({
      timeout: 90_000,
    })
    await pageB.keyboard.press('Escape')
    await pageC.getByTestId(`chat-group-${conversationId}`).click()
    await expect(
      pageC.getByPlaceholder('Only group administrators may send messages'),
    ).toBeDisabled({ timeout: 90_000 })

    // V1 cryptographic policy is monotonic: owners may tighten the canonical
    // application plaintext ceiling but cannot alter suite/padding/delivery.
    const cryptographicPolicyApprovalRequest = pageA.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'POST'
        && path === '/api/chat/mls/anonymous/messages'
    })
    await pageA.getByTestId('chat-group-members').click()
    await pageA.getByTestId('chat-group-maximum-plaintext').fill('1024')
    await pageA.getByTestId('chat-group-tighten-plaintext').click()
    expect((await requireResponseOrUiError(pageA, cryptographicPolicyApprovalRequest)).ok()).toBe(true)
    await pageA.keyboard.press('Escape')

    await pageB.getByTestId('chat-group-members').click()
    await expect(pageB.getByText('Approve stricter MLS message limits?')).toBeVisible({
      timeout: 90_000,
    })
    const cryptographicPolicyApprovalResponse = pageB.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'POST'
        && path === '/api/chat/mls/anonymous/messages'
    })
    const cryptographicPolicyCommit = pageA.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'POST'
        && path === '/api/chat/mls/control/blocks'
    })
    await pageB.getByTestId('chat-group-owner-approve').click()
    expect((await requireResponseOrUiError(pageB, cryptographicPolicyApprovalResponse)).ok()).toBe(true)
    expect((await requireResponseOrUiError(pageA, cryptographicPolicyCommit)).ok()).toBe(true)
    await pageB.keyboard.press('Escape')

    await pageA.getByTestId('chat-group-members').click()
    await expect(pageA.getByTestId('chat-group-maximum-plaintext')).toHaveValue('1024', {
      timeout: 90_000,
    })
    await pageA.keyboard.press('Escape')
    let oversizedSubmitted = false
    const observeOversized = (request: import('@playwright/test').Request) => {
      if (
        request.method() === 'POST'
        && new URL(request.url()).pathname === '/api/chat/mls/anonymous/messages'
      ) oversizedSubmitted = true
    }
    pageA.on('request', observeOversized)
    await send(pageA, 'x'.repeat(2048))
    await expect(pageA.locator('[data-sonner-toast][data-type="error"]')).toBeVisible({
      timeout: 15_000,
    })
    await pageA.waitForTimeout(1_000)
    expect(oversizedSubmitted).toBe(false)
    pageA.off('request', observeOversized)
    await expect(pageA.locator('[data-sonner-toast][data-type="error"]')).toHaveCount(0, {
      timeout: 15_000,
    })

    // Group-control traffic remains available under administrator-only
    // application policy. Bob removes the non-administrator before recovery.
    const administratorRemoveCommit = pageB.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'POST'
        && path === '/api/chat/mls/control/blocks'
    })
    await pageB.getByTestId('chat-group-members').click()
    await pageB.getByRole('button', {
      name: `Remove ${charlie}@a.test from group`,
    }).click()
    expect((await requireResponseOrUiError(pageB, administratorRemoveCommit)).ok()).toBe(true)
    await expect(
      pageB.getByTestId(`chat-group-member-${charlie}@a.test`),
    ).toHaveCount(0, { timeout: 90_000 })
    await pageB.keyboard.press('Escape')

    await pageA.getByTestId('chat-group-members').click()
    await expect(
      pageA.getByTestId(`chat-group-member-${charlie}@a.test`),
    ).toHaveCount(0, { timeout: 90_000 })
    await pageA.keyboard.press('Escape')

    let recoverySubmitted = false
    let awaitingRecoveryApproval = true
    pageA.on('request', (request) => {
      if (
        awaitingRecoveryApproval
        && request.method() === 'POST'
        && new URL(request.url()).pathname === '/api/chat/mls/conversations/recover'
      ) recoverySubmitted = true
    })
    const recoveryApprovalRequest = pageA.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'POST'
        && path === '/api/chat/mls/anonymous/messages'
    })
    await pageA.getByTestId('chat-group-members').click()
    pageA.once('dialog', dialog => void dialog.accept())
    await pageA.getByTestId('chat-group-recover').click()
    expect((await requireResponseOrUiError(pageA, recoveryApprovalRequest)).ok()).toBe(true)
    await pageA.waitForTimeout(1_000)
    expect(recoverySubmitted).toBe(false)

    await pageA.reload()
    await expect(pageA.getByRole('heading', { name: 'Messages' })).toBeVisible({ timeout: 90_000 })
    await pageA.getByTestId(`chat-group-${conversationId}`).click()

    await pageB.getByTestId('chat-group-members').click()
    await expect(pageB.getByText('Approve MLS group recovery?')).toBeVisible({ timeout: 90_000 })
    await pageB.reload()
    await expect(pageB.getByRole('heading', { name: 'Messages' })).toBeVisible({ timeout: 90_000 })
    await pageB.getByTestId(`chat-group-${conversationId}`).click()
    await pageB.getByTestId('chat-group-members').click()
    await expect(pageB.getByText('Approve MLS group recovery?')).toBeVisible({ timeout: 90_000 })

    const recoveryApprovalResponse = pageB.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'POST'
        && path === '/api/chat/mls/anonymous/messages'
    })
    const recoveryCommit = pageA.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'POST'
        && path === '/api/chat/mls/conversations/recover'
    })
    const destinationRecoveryEvidence = pageB.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'GET'
        && path === `/api/chat/mls/conversations/${conversationId}/2/recovery`
    })
    await pageB.getByTestId('chat-group-owner-approve').click()
    expect((await requireResponseOrUiError(pageB, recoveryApprovalResponse)).ok()).toBe(true)
    awaitingRecoveryApproval = false
    const recoveryResponse = await requireResponseOrUiError(pageA, recoveryCommit)
    expect(recoveryResponse.ok()).toBe(true)
    expect(await recoveryResponse.json()).toMatchObject({
      conversationId,
      previousIncarnation: 1,
      incarnation: 2,
      status: 'active',
    })
    expect((await destinationRecoveryEvidence).ok()).toBe(true)
    await pageB.keyboard.press('Escape')

    const afterRecoverySend = pageA.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'POST'
        && path === '/api/chat/mls/anonymous/messages'
    })
    const afterRecovery = `mls-after-recovery-${tag}`
    await send(pageA, afterRecovery)
    expect((await requireResponseOrUiError(pageA, afterRecoverySend)).ok()).toBe(true)
    await expect(bubble(pageB, afterRecovery)).toBeVisible({ timeout: 90_000 })

    await pageA.reload()
    await pageB.reload()
    await expect(pageA.getByRole('heading', { name: 'Messages' })).toBeVisible({ timeout: 90_000 })
    await expect(pageB.getByRole('heading', { name: 'Messages' })).toBeVisible({ timeout: 90_000 })
    await pageA.getByTestId(`chat-group-${conversationId}`).click()
    await pageB.getByTestId(`chat-group-${conversationId}`).click()
    await expect(bubble(pageA, afterRecovery)).toBeVisible({ timeout: 90_000 })
    await expect(bubble(pageB, afterRecovery)).toBeVisible({ timeout: 90_000 })

    let closeControlSubmitted = false
    let awaitingCloseApproval = true
    pageA.on('request', (request) => {
      if (
        awaitingCloseApproval
        && request.method() === 'POST'
        && new URL(request.url()).pathname === '/api/chat/mls/control/blocks'
      ) closeControlSubmitted = true
    })
    const closeApprovalRequest = pageA.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'POST'
        && path === '/api/chat/mls/anonymous/messages'
    })
    await pageA.getByTestId('chat-group-members').click()
    pageA.once('dialog', dialog => void dialog.accept())
    await pageA.getByTestId('chat-group-close').click()
    expect((await requireResponseOrUiError(pageA, closeApprovalRequest)).ok()).toBe(true)
    await pageA.waitForTimeout(1_000)
    expect(closeControlSubmitted).toBe(false)

    await pageA.reload()
    await expect(pageA.getByRole('heading', { name: 'Messages' })).toBeVisible({ timeout: 90_000 })
    await pageA.getByTestId(`chat-group-${conversationId}`).click()

    await pageB.getByTestId('chat-group-members').click()
    await expect(pageB.getByText('Approve closing this MLS group?')).toBeVisible({ timeout: 90_000 })
    await pageB.reload()
    await expect(pageB.getByRole('heading', { name: 'Messages' })).toBeVisible({ timeout: 90_000 })
    await pageB.getByTestId(`chat-group-${conversationId}`).click()
    await pageB.getByTestId('chat-group-members').click()
    await expect(pageB.getByText('Approve closing this MLS group?')).toBeVisible({ timeout: 90_000 })

    const closeApprovalResponse = pageB.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'POST'
        && path === '/api/chat/mls/anonymous/messages'
    })
    const closeCommit = pageA.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'POST'
        && path === '/api/chat/mls/control/blocks'
    })
    await pageB.getByTestId('chat-group-owner-approve').click()
    expect((await requireResponseOrUiError(pageB, closeApprovalResponse)).ok()).toBe(true)
    awaitingCloseApproval = false
    expect((await requireResponseOrUiError(pageA, closeCommit)).ok()).toBe(true)

    await expect(pageA.getByPlaceholder('This MLS group is closed')).toBeDisabled({
      timeout: 90_000,
    })
    await pageA.getByTestId('chat-group-members').click()
    await expect(pageA.getByTestId('chat-group-closed')).toBeVisible({ timeout: 90_000 })
    await expect(pageB.getByTestId('chat-group-closed')).toBeVisible({ timeout: 90_000 })
    await pageA.keyboard.press('Escape')
    await pageB.keyboard.press('Escape')
    await expect(pageA.getByPlaceholder('This MLS group is closed')).toBeDisabled()
    await expect(pageB.getByPlaceholder('This MLS group is closed')).toBeDisabled()

    await pageA.reload()
    await pageB.reload()
    await expect(pageA.getByRole('heading', { name: 'Messages' })).toBeVisible({ timeout: 90_000 })
    await expect(pageB.getByRole('heading', { name: 'Messages' })).toBeVisible({ timeout: 90_000 })
    await pageA.getByTestId(`chat-group-${conversationId}`).click()
    await pageB.getByTestId(`chat-group-${conversationId}`).click()
    await expect(pageA.getByPlaceholder('This MLS group is closed')).toBeDisabled()
    await expect(pageB.getByPlaceholder('This MLS group is closed')).toBeDisabled()

    expectNoPageErrors(pageA, pageA2, pageB, pageC, pageD)
    await contextA.close()
    await contextA2.close()
    await contextB.close()
    await contextC.close()
    await contextD.close()
  })
})
