import { expect, test, type Page, type Request, type Response } from '@playwright/test'
import { appUrl, hasSecondaryServer, newAccount, registerAccount, serverDomain, signIn } from '../fixtures/apps'
import {
  acceptRequest,
  closeDetails,
  composer,
  deleteForEveryone,
  editMessage,
  enableReadReceipts,
  message,
  openChat,
  openChats,
  openConversationWith,
  openDetails,
  openDirectChat,
  openGroup,
  openNoteToSelf,
  openSettings,
  reactTo,
  reaction,
  replyTo,
  send,
  sendAttachment,
  setDisappearing,
} from '../fixtures/chat'
import { recordSafeCheckpoint } from '../safe-diagnostics'

const PASSWORD = 'Deneme123*FederatedSecurityPassword'
const pageErrors = new WeakMap<Page, string[]>()

function sanitizedBrowserDiagnostic(value: string): string {
  return value
    .replace(/[\w.+-]+@[\w.-]+/g, '<account>')
    .replace(/\b[0-9a-f]{8}-[0-9a-f-]{27,}\b/gi, '<id>')
    .replace(/\b[A-Za-z0-9_-]{32,}\b/g, '<opaque>')
    .replace(/\bdevice\s+\d+\b/gi, 'device <n>')
    .slice(0, 500)
}

/** Records page errors and reports chat start-up failures, sanitized. */
function watchErrors(page: Page): void {
  const errors: string[] = []
  pageErrors.set(page, errors)
  page.on('pageerror', (error) => errors.push(error.stack ?? error.message))
  page.on('console', (entry) => {
    if (entry.type() !== 'error' || !entry.text().includes('Secure chat failed to initialize')) return
    void Promise.all(
      entry.args().map(async (argument) => {
        try {
          return await argument.evaluate((value) => {
            if (value instanceof Error) return `${value.name}: ${value.message}`
            return typeof value === 'string' ? value : ''
          })
        } catch {
          return ''
        }
      }),
    ).then((parts) => {
      console.error(`CHAT BROWSER INITIALIZATION FAILURE: ${sanitizedBrowserDiagnostic(parts.filter(Boolean).join(' ') || entry.text())}`)
    })
  })
}

function expectNoPageErrors(...pages: Page[]): void {
  expect(pages.flatMap((page) => pageErrors.get(page) ?? [])).toEqual([])
}

/**
 * The Rust/WASM runtimes are served with stable names, so a deployment must
 * make browsers revalidate them rather than pair an old ABI with a new page.
 */
async function expectWasmRuntimeRevalidation(page: Page): Promise<void> {
  for (const path of [
    '/chat-wasm/kutup_chat_core.js?runtime=2',
    '/chat-wasm/kutup_chat_core_bg.wasm?runtime=2',
    '/crypto-wasm/kutup_crypto_wasm.js?runtime=2',
    '/crypto-wasm/kutup_crypto_wasm_bg.wasm?runtime=2',
  ]) {
    const response = await page.evaluate(async (url) => {
      const result = await fetch(url, { method: 'HEAD', cache: 'no-store' })
      return { ok: result.ok, cacheControl: result.headers.get('cache-control') ?? '' }
    }, path)
    expect(response.ok, `${path} must be deployed with the page`).toBe(true)
    expect(response.cacheControl, `${path} must revalidate`).toContain('no-cache')
    expect(response.cacheControl, `${path} must not be immutable`).not.toContain('immutable')
  }
}

function posted(page: Page, pathname: string | RegExp): Promise<Response> {
  return page.waitForResponse((response) => {
    const path = new URL(response.url()).pathname
    return response.request().method() === 'POST' && (typeof pathname === 'string' ? path === pathname : pathname.test(path))
  })
}

const CONTROL = '/api/chat/mls/control/blocks'
const ANONYMOUS_MLS = '/api/chat/mls/anonymous/messages'

async function sendCapturedMedia(page: Page, filename: string, plaintext: string): Promise<void> {
  const input = page.getByTestId('chat-capture-input')
  await expect(input).toHaveAttribute('accept', 'image/*,video/*')
  await expect(input).toHaveAttribute('capture', 'environment')
  const delivery = posted(page, '/api/chat/media/deliveries')
  await input.setInputFiles({ name: filename, mimeType: 'image/png', buffer: Buffer.from(plaintext, 'utf8') })
  expect((await delivery).ok()).toBe(true)
}

async function installVoiceRecorderMock(page: Page, plaintext: string): Promise<void> {
  await page.evaluate((recordedPlaintext) => {
    type VoiceTestWindow = Window & { __kutupStoppedAudioTracks?: number }
    const target = window as VoiceTestWindow
    target.__kutupStoppedAudioTracks = 0
    Object.defineProperty(navigator, 'mediaDevices', {
      configurable: true,
      value: {
        getUserMedia: async () => ({
          getTracks: () => [
            {
              stop: () => {
                target.__kutupStoppedAudioTracks = (target.__kutupStoppedAudioTracks ?? 0) + 1
              },
            },
          ],
        }),
      },
    })
    class TestMediaRecorder {
      static isTypeSupported(mimeType: string) {
        return mimeType === 'audio/webm;codecs=opus'
      }

      readonly mimeType: string
      state: RecordingState = 'inactive'
      ondataavailable: ((event: BlobEvent) => void) | null = null
      onerror: ((event: Event) => void) | null = null
      onstop: ((event: Event) => void) | null = null

      constructor(_stream: MediaStream, options?: MediaRecorderOptions) {
        this.mimeType = options?.mimeType ?? 'audio/webm'
      }

      start() {
        this.state = 'recording'
      }

      stop() {
        this.state = 'inactive'
        // A WebM (EBML) header, as a real recorder writes, then the payload.
        const data = new Blob([new Uint8Array([0x1a, 0x45, 0xdf, 0xa3]), recordedPlaintext], { type: this.mimeType })
        this.ondataavailable?.({ data } as BlobEvent)
        this.onstop?.(new Event('stop'))
      }
    }
    Object.defineProperty(window, 'MediaRecorder', { configurable: true, value: TestMediaRecorder })
  }, plaintext)
}

function attachmentIn(page: Page, filename: string) {
  return page.getByTestId('chat-message').filter({ hasText: filename }).getByText(filename, { exact: true })
}

async function downloadAttachment(page: Page, filename: string): Promise<string> {
  // Chromium exposes the File System Access API, so Kutup streams decrypted
  // chunks into a picker-backed writable instead of building a Blob download.
  // A deterministic in-memory picker exercises that production path and lets
  // the test compare exact plaintext without a host save dialog.
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
          const view = data instanceof ArrayBuffer ? new Uint8Array(data) : new Uint8Array(data.buffer, data.byteOffset, data.byteLength)
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
  const moreActions = page.getByRole('button', { name: `More actions for ${filename}` })
  const cacheDownload = page.getByRole('button', {
    name: new RegExp(`^Download ${filename.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?: into Kutup)?$`),
    exact: true,
  })
  await expect
    .poll(async () => (await moreActions.isVisible()) || (await cacheDownload.isVisible()), {
      timeout: 45_000,
      message: `attachment ${filename} exposed neither cached nor remote actions`,
    })
    .toBe(true)
  if (!(await moreActions.isVisible())) await cacheDownload.click()
  await expect(moreActions).toBeVisible({ timeout: 45_000 })
  await moreActions.click()
  await page.getByRole('menuitem', { name: 'Save to device' }).click()
  await expect
    .poll(() => page.evaluate(() => (window as Window & { __kutupDownloadComplete?: boolean }).__kutupDownloadComplete === true), {
      timeout: 45_000,
      message: `download ${filename} did not finish`,
    })
    .toBe(true)
  return page.evaluate(() => {
    const chunks = (window as Window & { __kutupDownloadChunks?: number[][] }).__kutupDownloadChunks ?? []
    const plaintext = new Uint8Array(chunks.reduce((sum, chunk) => sum + chunk.length, 0))
    let offset = 0
    for (const chunk of chunks) {
      plaintext.set(chunk, offset)
      offset += chunk.length
    }
    return new TextDecoder().decode(plaintext)
  })
}

/**
 * Resolves with the response, or fails with the UI's error toast. The
 * orderer acknowledgement precedes the initiating client's durable OpenMLS
 * merge, so the UI is watched a little longer: a post-ack failure must not
 * pass as success.
 */
async function requireResponseOrUiError(page: Page, response: Promise<Response>): Promise<Response> {
  const uiError = page.locator('[data-sonner-toast][data-type="error"]')
  const errorText = uiError
    .waitFor({ state: 'visible', timeout: 15_000 })
    .then(async () => (await uiError.textContent())?.trim() || 'unknown error')
    .catch(() => undefined)
  const first = await Promise.race([
    response.then((value) => ({ kind: 'response' as const, value })),
    errorText.then((value) => ({ kind: 'error' as const, value })),
  ])
  if (first.kind === 'error') throw new Error(`browser operation failed: ${first.value ?? 'unknown error'}`)
  const lateError = await Promise.race([errorText, page.waitForTimeout(1_000).then(() => undefined)])
  if (lateError) throw new Error(`browser operation failed: ${lateError}`)
  return first.value
}

/** Opens the group's details (members, owners, authorities). */
async function openMembers(page: Page): Promise<void> {
  const panel = page.getByRole('region', { name: 'Chat details' })
  if (await panel.isVisible()) return
  await page.getByTestId('chat-group-members').click()
  await expect(panel).toBeVisible()
}

/** Confirms a destructive group action in its alert dialog. */
async function confirmAction(page: Page, submit: string): Promise<void> {
  await page.getByRole('alertdialog').getByRole('button', { name: submit, exact: true }).click()
}

async function reloadInto(page: Page, conversationId: string): Promise<void> {
  await page.reload()
  await openGroup(page, conversationId)
}

test.describe('two-server secure chat', () => {
  test.skip(!hasSecondaryServer(), 'set E2E_SECONDARY_APP_ORIGIN for the isolated federation topology')

  test('verifies the account pair, establishes sealed delivery, rotates capability, and never falls back', async ({ browser }) => {
    test.slow()
    const tag = Date.now() % 1_000_000
    const alice = newAccount('sealalice', PASSWORD, 'primary')
    const bob = newAccount('sealbob', PASSWORD, 'secondary')
    const bobAddress = `${bob.username}@${serverDomain('secondary')}`
    const abandonedContextA = await browser.newContext()
    const contextB = await browser.newContext()
    await registerAccount(abandonedContextA, alice)
    await registerAccount(contextB, bob)

    // An installation whose first manifest never reaches the server leaves an
    // unmanifested registration behind and says chat is unavailable.
    const abandonedPageA = await abandonedContextA.newPage()
    let interruptedManifestAttempts = 0
    await abandonedPageA.route('**/api/chat/manifest', async (route) => {
      if (route.request().method() === 'POST') {
        interruptedManifestAttempts += 1
        await route.abort('connectionfailed')
        return
      }
      await route.continue()
    })
    await abandonedPageA.goto(appUrl('chat', '/', 'primary'))
    await expect(abandonedPageA.getByText('Secure chat is temporarily unavailable.').first()).toBeVisible({ timeout: 90_000 })
    expect(interruptedManifestAttempts).toBeGreaterThan(0)
    await abandonedContextA.close()

    // A different installation must be able to recover the abandoned,
    // unmanifested server registration. Its authority-signed first manifest
    // selects only its own exact key tuple and atomically prunes the orphan.
    const contextA = await browser.newContext()
    await signIn(contextA, alice)
    const pageA = await openChat(contextA, 'primary', watchErrors)
    const pageB = await openChat(contextB, 'secondary', watchErrors)
    await enableReadReceipts(pageB)
    await expectWasmRuntimeRevalidation(pageA)
    await expectWasmRuntimeRevalidation(pageB)

    const identifiedToBob: string[] = []
    pageA.on('request', (request) => {
      const path = new URL(request.url()).pathname
      if (request.method() === 'POST' && path.includes('/api/chat/users/') && path.endsWith('/messages')) identifiedToBob.push(path)
    })

    await openDirectChat(pageA, bobAddress)
    // V1 does not allocate destination media for a message request. Direct
    // attachments become available only after the contact is accepted.
    await expect(pageA.getByTestId('chat-attachment-button')).toHaveCount(0)
    await expect(pageA.getByTestId('chat-attachment-input')).toHaveCount(0)
    await expect(pageA.getByTestId('chat-voice-button')).toHaveCount(0)
    const firstIdentified = posted(pageA, /\/api\/chat\/users\/.+\/messages$/)
    const first = `identified-first-${tag}`
    await send(pageA, first)
    expect((await firstIdentified).ok()).toBe(true)
    await openConversationWith(pageB, alice.username)
    await expect(message(pageB, first)).toBeVisible({ timeout: 45_000 })
    await acceptRequest(pageB)

    // The server can distribute signed manifests but cannot promote trust.
    // Both installations independently derive the same full pair/key binding;
    // only an exact face-to-face QR exchange turns the gray shields green.
    await openDetails(pageA)
    await pageA.getByTestId('chat-safety-open').click()
    const safetyA = pageA.getByRole('dialog')
    const qrA = await safetyA.getByTestId('chat-safety-qr').getAttribute('data-value')
    expect(qrA).toMatch(/^kutup:\/\/verify\/chat\/v1\//)
    await openDetails(pageB)
    await pageB.getByTestId('chat-safety-open').click()
    const safetyB = pageB.getByRole('dialog')
    const qrB = await safetyB.getByTestId('chat-safety-qr').getAttribute('data-value')
    expect(qrB).toBe(qrA)
    await safetyB.getByPlaceholder('kutup://verify/chat/v1/…').fill(qrA!)
    await safetyB.getByRole('button', { name: 'Verify exact match' }).click()
    await expect(safetyB.getByText('Verified face to face on this device.')).toBeVisible()
    await pageB.keyboard.press('Escape')
    await closeDetails(pageB)
    await safetyA.getByPlaceholder('kutup://verify/chat/v1/…').fill(qrB!)
    await safetyA.getByRole('button', { name: 'Verify exact match' }).click()
    await expect(safetyA.getByText('Verified face to face on this device.')).toBeVisible()
    await pageA.keyboard.press('Escape')
    await closeDetails(pageA)

    const typingDraft = `typing-only-${tag}`
    await composer(pageB).fill(typingDraft)
    await expect(pageA.getByTestId('chat-typing-indicator')).toContainText(bob.username, { timeout: 45_000 })
    await expect(pageA.getByText(typingDraft)).toHaveCount(0)

    const sealedReplyResponse = posted(pageB, /\/api\/chat\/anonymous\/users\/.+\/messages$/)
    const reply = `sealed-reply-${tag}`
    await send(pageB, reply)
    expect((await sealedReplyResponse).ok()).toBe(true)
    // The acceptance/profile update and immediate sealed reply use independent
    // durable paths. Reconciliation must recover either arrival order.
    await expect(message(pageA, reply)).toBeVisible({ timeout: 45_000 })
    await expect(pageA.getByTestId('chat-typing-indicator')).toHaveCount(0, { timeout: 45_000 })
    await expect(message(pageB, reply).getByTestId('chat-receipt-delivered')).toBeVisible({ timeout: 45_000 })

    // Search reads only the already-decrypted browser history. The unique
    // query must find and navigate to the message without appearing in any
    // request URL or body.
    const searchTraffic: string[] = []
    const captureSearchTraffic = (request: Request) => {
      searchTraffic.push(`${request.url()}\n${request.postData() ?? ''}`)
    }
    pageA.on('request', captureSearchTraffic)
    await pageA.getByTestId('chat-search-input').fill(reply)
    const searchResult = pageA.getByTestId('chat-search-result').filter({ hasText: reply })
    await expect(searchResult).toHaveCount(1)
    await searchResult.click()
    await expect(message(pageA, reply)).toBeVisible()
    pageA.off('request', captureSearchTraffic)
    expect(searchTraffic.join('\n')).not.toContain(reply)

    // Timer state and each affected duration are authenticated inside the
    // ordinary Direct ciphertext. Alice counts from send; Bob remains unread
    // until the bubble is actually visible, then privately synchronizes that
    // absolute first-view deadline to Bob's own linked devices.
    await setDisappearing(pageA, 'thirtySeconds')
    await expect(pageA.getByTestId('chat-disappearing-timer')).toHaveAccessibleName('New messages disappear after 30 seconds')
    await expect(pageB.getByTestId('chat-disappearing-timer')).toHaveAccessibleName('New messages disappear after 30 seconds', { timeout: 45_000 })
    await openNoteToSelf(pageB)
    const temporary = `temporary-direct-${tag}`
    await send(pageA, temporary)
    await expect(message(pageA, temporary).getByTestId('chat-message-expiry')).toBeVisible({ timeout: 45_000 })
    await expect
      .poll(async () => await message(pageA, temporary).count(), {
        timeout: 60_000,
        intervals: [1_000],
        message: 'sender disappearing plaintext outlived its authenticated duration',
      })
      .toBe(0)
    await openConversationWith(pageB, alice.username)
    await expect(message(pageB, temporary)).toBeVisible({ timeout: 45_000 })
    await expect(message(pageB, temporary).getByTestId('chat-message-expiry')).toBeVisible()
    await expect
      .poll(async () => await message(pageB, temporary).count(), {
        timeout: 60_000,
        intervals: [1_000],
        message: 'recipient disappearing plaintext outlived its first-view duration',
      })
      .toBe(0)
    await setDisappearing(pageA, 'off')
    await expect(pageB.getByTestId('chat-disappearing-timer')).toHaveAccessibleName('Disappearing messages are off', { timeout: 45_000 })

    const destinationEnvelopes: Array<Record<string, unknown>> = []
    pageB.on('response', (response) => {
      const url = new URL(response.url())
      if (response.request().method() !== 'GET' || url.pathname !== '/api/chat/messages' || !response.ok()) return
      void response
        .json()
        .then((body: { envelopes?: Array<Record<string, unknown>> }) => {
          destinationEnvelopes.push(...(body.envelopes ?? []))
        })
        .catch(() => {})
    })
    identifiedToBob.length = 0
    const sealedSendResponse = posted(pageA, /\/api\/chat\/anonymous\/users\/.+\/messages$/)
    const sealed = `sealed-second-${tag}`
    await send(pageA, sealed)
    expect((await sealedSendResponse).ok()).toBe(true)
    await expect.poll(() => destinationEnvelopes.some((envelope) => envelope.sealedSender === true), { timeout: 45_000 }).toBe(true)
    const destinationEnvelope = destinationEnvelopes.find((envelope) => envelope.sealedSender === true)
    expect(destinationEnvelope).not.toHaveProperty('sender')
    expect(destinationEnvelope?.senderDeviceId).toBe(0)
    await expect(message(pageB, sealed)).toBeVisible({ timeout: 45_000 })
    await expect(message(pageA, sealed).getByTestId('chat-receipt-read')).toBeVisible({ timeout: 45_000 })
    const quotedReply = `sealed-quoted-reply-${tag}`
    await replyTo(pageB, sealed, quotedReply)
    await expect(message(pageA, quotedReply)).toBeVisible({ timeout: 45_000 })
    await expect(message(pageA, quotedReply).getByTestId('chat-reply-context')).toContainText(sealed)

    await reactTo(pageB, sealed, '👍')
    await expect(reaction(pageA, sealed, '👍')).toHaveAttribute('data-count', '1', { timeout: 45_000 })
    await reactTo(pageA, sealed, '👍')
    await expect(reaction(pageB, sealed, '👍')).toHaveAttribute('data-count', '2', { timeout: 45_000 })
    await message(pageB, sealed).hover()
    await message(pageB, sealed).getByTestId('chat-reaction-button').click()
    await pageB.getByRole('menuitem', { name: '👍 Remove' }).click()
    await expect(reaction(pageA, sealed, '👍')).toHaveAttribute('data-count', '1', { timeout: 45_000 })
    const editedSealed = `edited-sealed-${tag}`
    await editMessage(pageA, sealed, editedSealed)
    await expect(message(pageB, editedSealed)).toBeVisible({ timeout: 45_000 })
    await expect(message(pageB, editedSealed).getByTestId('chat-message-edited')).toBeVisible()
    await deleteForEveryone(pageA, editedSealed)
    await expect(message(pageB, editedSealed)).toHaveCount(0, { timeout: 45_000 })
    await expect(pageB.getByTestId('chat-message-deleted')).toHaveCount(1)
    expect(identifiedToBob).toEqual([])

    const directAttachment = `direct-attachment-${tag}.txt`
    const directAttachmentBody = `federated encrypted attachment ${tag}`
    await expect(pageA.getByTestId('chat-attachment-button')).toBeEnabled({ timeout: 45_000 })
    await sendAttachment(pageA, directAttachment, directAttachmentBody)
    await expect(attachmentIn(pageB, directAttachment)).toBeVisible({ timeout: 90_000 })
    expect(await downloadAttachment(pageB, directAttachment)).toBe(directAttachmentBody)

    const capturedPhoto = `captured-photo-${tag}.png`
    const capturedPhotoBody = `native camera bytes encrypted before upload ${tag}`
    await sendCapturedMedia(pageA, capturedPhoto, capturedPhotoBody)
    await expect(attachmentIn(pageB, capturedPhoto)).toBeVisible({ timeout: 90_000 })
    expect(await downloadAttachment(pageB, capturedPhoto)).toBe(capturedPhotoBody)

    const voiceNoteBody = `microphone audio encrypted before upload ${tag}`
    await installVoiceRecorderMock(pageA, voiceNoteBody)
    await pageA.getByTestId('chat-voice-button').click()
    await expect(pageA.getByTestId('chat-voice-recording')).toBeVisible()
    await pageA.getByTestId('chat-voice-cancel').click()
    await expect(pageA.getByTestId('chat-voice-recording')).toBeHidden()
    await expect.poll(() => pageA.evaluate(() => (window as Window & { __kutupStoppedAudioTracks?: number }).__kutupStoppedAudioTracks)).toBe(1)

    await pageA.getByTestId('chat-voice-button').click()
    await expect(pageA.getByTestId('chat-voice-recording')).toBeVisible()
    const voiceDelivery = posted(pageA, '/api/chat/media/deliveries')
    await pageA.getByTestId('chat-voice-stop').click()
    expect((await voiceDelivery).ok()).toBe(true)
    // Voice notes show as a player; its controls are named after the file.
    const voiceDownload = pageB.getByRole('button', { name: /^Download voice-note-[0-9]+\.webm$/ }).last()
    await expect(voiceDownload).toBeVisible({ timeout: 90_000 })
    const voiceFilename = (await voiceDownload.getAttribute('aria-label'))!.replace(/^Download /, '')
    await voiceDownload.click()
    await pageB.getByRole('button', { name: `Play ${voiceFilename}` }).click({ timeout: 45_000 })
    // The player decrypts into a local blob before playback: read it back.
    await expect
      .poll(
        () =>
          pageB.evaluate(async () => {
            const audio = [...document.querySelectorAll('audio')].find((element) => element.src.startsWith('blob:'))
            if (!audio) return null
            const bytes = new Uint8Array(await (await fetch(audio.src)).arrayBuffer())
            if (bytes[0] !== 0x1a || bytes[1] !== 0x45 || bytes[2] !== 0xdf || bytes[3] !== 0xa3) return 'not webm'
            return new TextDecoder().decode(bytes.subarray(4))
          }),
        { timeout: 45_000 },
      )
      .toBe(voiceNoteBody)
    await expect.poll(() => pageA.evaluate(() => (window as Window & { __kutupStoppedAudioTracks?: number }).__kutupStoppedAudioTracks)).toBe(2)

    await openSettings(pageB, 'Storage')
    await expect(pageB.getByTestId('chat-storage-summary')).toBeVisible({ timeout: 45_000 })
    await expect(pageB.getByText('Delivery media', { exact: true })).toBeVisible()
    await expect(pageB.getByText('History media', { exact: true })).toBeVisible()
    await pageB.getByRole('button', { name: /^Clear stored Chat media for / }).first().click()
    await confirmAction(pageB, 'Clear')
    await expect(pageB.getByText('No chat attachments stored yet.')).toBeVisible({ timeout: 45_000 })
    // Clearing temporary delivery storage must not evict the recipient's
    // already-verified local cache or the independently protected history
    // copy. The unavailable-media recovery spec covers both sources missing.
    await openConversationWith(pageB, alice.username)
    expect(await downloadAttachment(pageB, directAttachment)).toBe(directAttachmentBody)

    const noteAttachment = `note-attachment-${tag}.txt`
    const noteAttachmentBody = `encrypted note to self attachment ${tag}`
    await openNoteToSelf(pageA)
    await expect(pageA.getByTestId('chat-attachment-button')).toBeEnabled()
    await sendAttachment(pageA, noteAttachment, noteAttachmentBody, { delivered: false })
    await expect(attachmentIn(pageA, noteAttachment)).toBeVisible({ timeout: 90_000 })
    expect(await downloadAttachment(pageA, noteAttachment)).toBe(noteAttachmentBody)

    await openConversationWith(pageA, bob.username)

    // Blocking publishes the new profile key/capability before returning.
    // Alice's stolen/stale capability receives the uniform 404 and the
    // established conversation must not attempt the identified endpoint.
    await openDetails(pageB)
    await pageB.getByRole('button', { name: /^Block / }).click()
    await expect(pageB.getByRole('button', { name: 'Unblock', exact: true }).first()).toBeVisible({ timeout: 45_000 })
    await closeDetails(pageB)
    identifiedToBob.length = 0
    const rejectedAnonymous = pageA.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return (
        response.request().method() === 'POST' &&
        path.includes('/api/chat/anonymous/users/') &&
        (path.endsWith('/keys') || path.endsWith('/messages')) &&
        response.status() === 404
      )
    })
    await send(pageA, `rejected-stale-capability-${tag}`)
    await rejectedAnonymous
    await pageA.waitForTimeout(1_000)
    expect(identifiedToBob).toEqual([])
    await expect(message(pageB, `rejected-stale-capability-${tag}`)).toHaveCount(0)

    expectNoPageErrors(pageA, pageB)
    await contextA.close()
    await contextB.close()
  })

  test('manages a federated MLS group and exchanges anonymous durable messages', async ({ browser }) => {
    // This is the exhaustive MLS browser gate: the full governance and
    // recovery sequence needs more than the six-minute slow-test budget.
    test.setTimeout(600_000)
    const tag = Date.now() % 1_000_000
    const alice = newAccount('mlsalice', PASSWORD, 'primary')
    const bob = newAccount('mlsbob', PASSWORD, 'secondary')
    const charlie = newAccount('mlscarol', PASSWORD, 'primary')
    const dave = newAccount('mlsdave', PASSWORD, 'secondary')
    const a = serverDomain('primary')
    const b = serverDomain('secondary')
    const aliceAddress = `${alice.username}@${a}`
    const bobAddress = `${bob.username}@${b}`
    const charlieAddress = `${charlie.username}@${a}`
    const daveAddress = `${dave.username}@${b}`
    const groupName = `Security ${tag}`
    const contextA = await browser.newContext()
    const contextB = await browser.newContext()
    const contextC = await browser.newContext()
    const contextD = await browser.newContext()
    await registerAccount(contextA, alice)
    await registerAccount(contextB, bob)
    await registerAccount(contextC, charlie)
    await registerAccount(contextD, dave)
    const pageA = await openChat(contextA, 'primary', watchErrors)
    const pageB = await openChat(contextB, 'secondary', watchErrors)
    await enableReadReceipts(pageB)
    const pageC = await openChat(contextC, 'primary', watchErrors)
    const pageD = await openChat(contextD, 'secondary', watchErrors)

    const genesisResponse = posted(pageA, '/api/chat/mls/conversations')
    const identifiedPackages = posted(pageA, '/api/chat/mls/key-packages/identified')
    const membershipCommit = posted(pageA, CONTROL)
    await pageA.getByRole('button', { name: 'New chat' }).first().click()
    await pageA.getByRole('dialog').getByTestId('chat-create-group').click()
    await pageA.getByTestId('chat-group-name').fill(groupName)
    await pageA.getByTestId('chat-group-initial-member').fill(bobAddress)
    await pageA.getByTestId('chat-group-create-submit').click()
    const genesis = await genesisResponse
    expect(genesis.ok()).toBe(true)
    const { conversationId } = (await genesis.json()) as { conversationId: string }
    const genesisRequest = genesis.request().postDataJSON() as {
      genesis: {
        authoritySet: { authorities: Array<{ domain: string; keyId: string; publicKey: string }> }
        ownerSet: { owners: Array<{ ownerId: string; publicKey: string }> }
      }
    }
    expect(conversationId).toMatch(/^[0-9a-f-]{36}$/)
    const identifiedPackageResponse = await identifiedPackages
    expect(identifiedPackageResponse.ok()).toBe(true)
    const identifiedPackageRequest = identifiedPackageResponse.request().postDataJSON()
    expect((await membershipCommit).ok()).toBe(true)
    await expect(pageA.getByTestId(`chat-group-${conversationId}`)).toBeVisible({ timeout: 90_000 })
    await expect(pageA.getByTestId('chat-group-delivery-readiness')).toContainText('Waiting for 1 invited member to accept')
    await expect(composer(pageA)).toHaveCount(0)

    // No manual sync: the destination server sends only a generic
    // DrainMailbox WebSocket hint after committing the federated Welcome.
    await expect(pageB.getByTestId('chat-group-invitations')).toBeVisible({ timeout: 90_000 })
    const invitationAcceptance = posted(pageB, '/api/chat/mls/invitations')
    await pageB.getByTestId('chat-group-accept').click()
    const invitationAcceptanceResponse = await invitationAcceptance
    expect(invitationAcceptanceResponse.ok()).toBe(true)
    await openGroup(pageB, conversationId)
    await expect(pageA.getByTestId('chat-group-delivery-readiness')).toHaveCount(0, { timeout: 90_000 })
    recordSafeCheckpoint('two-server-mls', 'initial-membership-established', { members: 2 })

    // The member-visible security panel must show exact group owner
    // credentials and group-pinned authority keys, then independently verify
    // the complete federation identity/policy history before showing live
    // policy and identity fingerprints. Assertions compare the UI against the
    // signed genesis and actual two-server policy responses, not fixtures.
    const policyResponseFor = (domain: string) =>
      pageA.waitForResponse((response) => {
        const path = new URL(response.url()).pathname
        return response.request().method() === 'GET' && path === `/api/chat/mls/domains/${domain}/policy` && response.ok()
      })
    const aPolicyResponse = policyResponseFor(a)
    const bPolicyResponse = policyResponseFor(b)
    await openMembers(pageA)
    const [aPolicyHistory, bPolicyHistory] = (await Promise.all([
      aPolicyResponse.then((response) => response.json()),
      bPolicyResponse.then((response) => response.json()),
    ])) as Array<{
      identities: Array<{ sequence: number; key: { keyId: string; publicKey: string } }>
      policies: Array<{ sequence: number; federationIdentityGeneration: number; payload: string }>
    }>
    const assertExactAuthoritySecurity = async (domain: string, history: typeof aPolicyHistory) => {
      const envelope = history.policies.at(-1)
      expect(envelope).toBeDefined()
      const policy = JSON.parse(Buffer.from(envelope!.payload, 'base64').toString('utf8')) as {
        controlSigningKeyId: string
        controlSigningPublicKey: string
        maximumGroupMembers: number
      }
      const identity = history.identities.find((candidate) => candidate.sequence === envelope!.federationIdentityGeneration)
      expect(identity).toBeDefined()
      const genesisAuthority = genesisRequest.genesis.authoritySet.authorities.find((candidate) => candidate.domain === domain)
      expect(genesisAuthority).toBeDefined()
      expect(policy.controlSigningKeyId).toBe(genesisAuthority!.keyId)
      expect(policy.controlSigningPublicKey).toBe(genesisAuthority!.publicKey)
      await expect(pageA.getByTestId(`chat-group-authority-policy-match-${domain}`)).toBeVisible({ timeout: 90_000 })
      await expect(pageA.getByTestId(`chat-group-authority-pin-${domain}`)).toContainText(genesisAuthority!.keyId)
      const exactPolicy = pageA.getByTestId(`chat-group-authority-policy-${domain}`)
      await exactPolicy.getByText('Exact authenticated service policy').click()
      await expect(pageA.getByTestId(`chat-group-authority-policy-fingerprint-${domain}`)).toContainText(policy.controlSigningKeyId)
      await expect(pageA.getByTestId(`chat-group-authority-identity-fingerprint-${domain}`)).toContainText(identity!.key.keyId)
      await expect(pageA.getByTestId(`chat-group-authority-policy-sequence-${domain}`)).toContainText(String(envelope!.sequence))
      await expect(pageA.getByTestId(`chat-group-authority-${domain}`)).toContainText(String(policy.maximumGroupMembers))
      await exactPolicy.getByText('Exact authenticated service policy').click()
    }
    const genesisOwner = genesisRequest.genesis.ownerSet.owners[0]
    expect(genesisOwner).toBeDefined()
    await expect(pageA.getByTestId(`chat-group-owner-fingerprint-${aliceAddress}`)).toContainText(genesisOwner.ownerId)
    await expect(pageA.getByTestId(`chat-group-owner-credential-${aliceAddress}`)).toContainText(genesisOwner.publicKey)
    await assertExactAuthoritySecurity(a, aPolicyHistory)
    await assertExactAuthoritySecurity(b, bPolicyHistory)
    await closeDetails(pageA)

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
            headers: { Authorization: authorization!, 'Content-Type': 'application/json' },
            body: JSON.stringify(request),
          })
          return response.status
        }
        return {
          self: await claim(selfRequest),
          crossAccount: await claim({ ...selfRequest, recipient: crossAccountRecipient }),
        }
      },
      {
        authorization: bobAuthorization,
        selfRequest: identifiedPackageRequest,
        crossAccountRecipient: { username: alice.username, server: a },
      },
    )
    expect(packageClaimStatuses.self).toBe(200)
    expect(packageClaimStatuses.crossAccount).toBe(403)

    // Routine administrator changes use the same encrypted roster transition,
    // but preserve member count and routing domains and require no owner vote.
    const administratorCommit = posted(pageA, CONTROL)
    await openMembers(pageA)
    const bobOnAlice = pageA.getByTestId(`chat-group-member-${bobAddress}`)
    await bobOnAlice.getByRole('button', { name: /^Make .* an administrator$/ }).click()
    expect((await requireResponseOrUiError(pageA, administratorCommit)).ok()).toBe(true)
    await expect(bobOnAlice.getByText('Administrator', { exact: true })).toBeVisible({ timeout: 90_000 })
    await closeDetails(pageA)

    await openMembers(pageB)
    await expect(pageB.getByTestId(`chat-group-member-${bobAddress}`).getByText('Administrator', { exact: true })).toBeVisible({
      timeout: 90_000,
    })

    const administratorAddCommit = posted(pageB, CONTROL)
    await pageB.getByTestId('chat-group-add-member').click()
    await pageB.getByLabel('Group member address').fill(charlieAddress)
    await pageB.getByRole('button', { name: 'Invite member' }).click()
    expect((await requireResponseOrUiError(pageB, administratorAddCommit)).ok()).toBe(true)
    await closeDetails(pageB)
    await expect(pageC.getByTestId('chat-group-invitations')).toBeVisible({ timeout: 90_000 })
    await pageC.getByTestId('chat-group-accept').click()
    await expect(pageC.getByTestId(`chat-group-${conversationId}`)).toBeVisible({ timeout: 90_000 })
    // Charlie was invited by Bob on the second server, so Alice's server does
    // not receive the plaintext origin-scoped receipt. Alice unlocks only after
    // processing Charlie's MLS-encrypted, exact-join-epoch acceptance.
    await expect(pageA.getByTestId('chat-group-delivery-readiness')).toHaveCount(0, { timeout: 90_000 })

    await openMembers(pageA)
    await expect(pageA.getByTestId(`chat-group-member-${charlieAddress}`)).toBeVisible({ timeout: 90_000 })
    await closeDetails(pageA)

    // A rejected cross-server Welcome produces durable, federation-authenticated
    // advisory feedback. It cannot mutate the MLS roster: Alice must see the
    // exact member warning and manually commit the cryptographic removal.
    const rejectedMemberAddCommit = posted(pageA, CONTROL)
    await openMembers(pageA)
    await pageA.getByTestId('chat-group-add-member').click()
    await pageA.getByLabel('Group member address').fill(daveAddress)
    await pageA.getByRole('button', { name: 'Invite member' }).click()
    const rejectedMemberAddResponse = await requireResponseOrUiError(pageA, rejectedMemberAddCommit)
    expect(rejectedMemberAddResponse.ok()).toBe(true)
    await closeDetails(pageA)
    const aliceAuthorization = await rejectedMemberAddResponse.request().headerValue('authorization')
    expect(aliceAuthorization).toMatch(/^Bearer /)
    await expect(pageD.getByTestId('chat-group-invitations')).toBeVisible({ timeout: 90_000 })
    const invitationRejection = posted(pageD, '/api/chat/mls/invitations')
    await pageD.getByTestId('chat-group-invitations').getByRole('button', { name: 'Reject' }).click()
    expect((await invitationRejection).ok()).toBe(true)
    await expect(pageD.getByTestId('chat-group-invitations')).toHaveCount(0)

    await expect
      .poll(
        () =>
          pageA.evaluate(
            async ({ authorization, groupId, member }) => {
              const response = await fetch('/api/chat/mls/invitation-feedback', { headers: { Authorization: authorization! } })
              if (!response.ok) return false
              const feedback = (await response.json()) as Array<{
                conversationId: string
                member: { username: string; server?: string }
                decision: string
              }>
              return feedback.some(
                (entry) =>
                  entry.conversationId === groupId && `${entry.member.username}@${entry.member.server}` === member && entry.decision === 'rejected',
              )
            },
            { authorization: aliceAuthorization, groupId: conversationId, member: daveAddress },
          ),
        { timeout: 90_000 },
      )
      .toBe(true)

    await reloadInto(pageA, conversationId)
    await openMembers(pageA)
    await expect(pageA.getByTestId(`chat-group-invitation-feedback-${daveAddress}`)).toContainText('Rejected the invitation', { timeout: 90_000 })
    const rejectedMemberRemoveCommit = posted(pageA, CONTROL)
    await pageA.getByTestId(`chat-group-member-${daveAddress}`).getByRole('button', { name: /^Remove .* from the group$/ }).click()
    expect((await requireResponseOrUiError(pageA, rejectedMemberRemoveCommit)).ok()).toBe(true)
    await expect(pageA.getByTestId(`chat-group-member-${daveAddress}`)).toHaveCount(0, { timeout: 90_000 })
    await closeDetails(pageA)
    recordSafeCheckpoint('two-server-mls', 'membership-governance-completed', { members: 3 })

    // Promote Bob while the current owner set is Alice-only (q=1), then prove
    // the resulting two-owner set (q=2) cannot remove Bob until his exact
    // encrypted manual approval returns. Both clients restart with the
    // partially approved transition/request still durable.
    const promoteOwnerCommit = posted(pageA, CONTROL)
    await openMembers(pageA)
    await pageA.getByTestId(`chat-group-owner-${bobAddress}`).click()
    expect((await requireResponseOrUiError(pageA, promoteOwnerCommit)).ok()).toBe(true)
    await expect(pageA.getByTestId(`chat-group-member-owner-${bobAddress}`)).toBeVisible({ timeout: 90_000 })
    await closeDetails(pageA)

    await openMembers(pageB)
    await expect(pageB.getByTestId(`chat-group-member-owner-${bobAddress}`)).toBeVisible({ timeout: 90_000 })
    await closeDetails(pageB)

    let ownerRemovalControlSubmitted = false
    let awaitingOwnerRemovalApproval = true
    pageA.on('request', (request) => {
      if (awaitingOwnerRemovalApproval && request.method() === 'POST' && new URL(request.url()).pathname === CONTROL) {
        ownerRemovalControlSubmitted = true
      }
    })
    const ownerApprovalRequest = posted(pageA, ANONYMOUS_MLS)
    await openMembers(pageA)
    await pageA.getByTestId(`chat-group-owner-${bobAddress}`).click()
    expect((await requireResponseOrUiError(pageA, ownerApprovalRequest)).ok()).toBe(true)
    await pageA.waitForTimeout(1_000)
    expect(ownerRemovalControlSubmitted).toBe(false)
    await reloadInto(pageA, conversationId)

    await openMembers(pageB)
    await expect(pageB.getByTestId('chat-group-owner-approval')).toBeVisible({ timeout: 90_000 })
    await reloadInto(pageB, conversationId)
    await openMembers(pageB)
    await expect(pageB.getByTestId('chat-group-owner-approval')).toBeVisible({ timeout: 90_000 })

    const ownerApprovalResponse = posted(pageB, ANONYMOUS_MLS)
    const removeOwnerCommit = posted(pageA, CONTROL)
    await pageB.getByTestId('chat-group-owner-approve').click()
    expect((await requireResponseOrUiError(pageB, ownerApprovalResponse)).ok()).toBe(true)
    awaitingOwnerRemovalApproval = false
    expect((await requireResponseOrUiError(pageA, removeOwnerCommit)).ok()).toBe(true)
    await closeDetails(pageB)

    await openMembers(pageA)
    await expect(pageA.getByTestId(`chat-group-member-owner-${bobAddress}`)).toHaveCount(0, { timeout: 90_000 })
    await closeDetails(pageA)
    recordSafeCheckpoint('two-server-mls', 'owner-quorum-completed', { owners: 1 })

    // The owner changes ordering authorities through one owner-approved MLS
    // Commit and joint old/new quorums. Removing the second server still
    // delivers the exact Commit to Bob because participant routing is
    // independent from the ordering set.
    const removeAuthorityCommit = posted(pageA, CONTROL)
    await openMembers(pageA)
    await pageA.getByTestId('chat-group-authority-domains').fill(a)
    await pageA.getByTestId('chat-group-save-authorities').click()
    expect((await requireResponseOrUiError(pageA, removeAuthorityCommit)).ok()).toBe(true)
    await expect(pageA.getByTestId(`chat-group-authority-${a}`)).toBeVisible({ timeout: 90_000 })
    await expect(pageA.getByTestId(`chat-group-authority-${b}`)).toHaveCount(0)
    await closeDetails(pageA)

    await openMembers(pageB)
    await expect(pageB.getByTestId(`chat-group-authority-${a}`)).toBeVisible({ timeout: 90_000 })
    await expect(pageB.getByTestId(`chat-group-authority-${b}`)).toHaveCount(0)
    await closeDetails(pageB)

    // Adding the second server back exercises exact history bootstrap before
    // it may contribute its new-set vote. Both participant clients then pin
    // sequence 3.
    const addAuthorityCommit = posted(pageA, CONTROL)
    await openMembers(pageA)
    await pageA.getByTestId('chat-group-authority-domains').fill(`${a}, ${b}`)
    await pageA.getByTestId('chat-group-save-authorities').click()
    expect((await requireResponseOrUiError(pageA, addAuthorityCommit)).ok()).toBe(true)
    await expect(pageA.getByTestId(`chat-group-authority-${b}`)).toBeVisible({ timeout: 90_000 })
    await closeDetails(pageA)

    await openMembers(pageB)
    await expect(pageB.getByTestId(`chat-group-authority-${b}`)).toBeVisible({ timeout: 90_000 })
    await closeDetails(pageB)
    recordSafeCheckpoint('two-server-mls', 'authority-rotation-completed', { authorities: 2 })

    const destinationMailbox: Array<Record<string, unknown>> = []
    pageB.on('response', (response) => {
      const url = new URL(response.url())
      if (response.request().method() !== 'GET' || !/^\/api\/chat\/mls\/messages\/\d+$/.test(url.pathname) || !response.ok()) return
      void response
        .json()
        .then((body: { envelopes?: Array<Record<string, unknown>> }) => {
          destinationMailbox.push(...(body.envelopes ?? []))
        })
        .catch(() => {})
    })

    await expect(pageA.locator('[data-sonner-toast][data-type="error"]')).toHaveCount(0)

    const sentToBob = posted(pageA, ANONYMOUS_MLS)
    const fromAlice = `mls-from-alice-${tag}`
    await send(pageA, fromAlice)
    const firstAnonymousResponse = await requireResponseOrUiError(pageA, sentToBob)
    expect(firstAnonymousResponse.ok()).toBe(true)
    const firstAnonymousSubmission = firstAnonymousResponse.request().postDataJSON() as Record<string, unknown>
    await expect(message(pageB, fromAlice)).toBeVisible({ timeout: 90_000 })
    await expect(message(pageA, fromAlice).getByTestId('chat-receipt-read')).toBeVisible({ timeout: 45_000 })
    await expect.poll(() => destinationMailbox.some((envelope) => envelope.deliveryKind === 'anonymous'), { timeout: 45_000 }).toBe(true)
    const anonymous = destinationMailbox.find((envelope) => envelope.deliveryKind === 'anonymous')
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
    await expect(message(pageB, fromAlice)).toHaveCount(1)

    const conflictingReplay = await pageA.evaluate(async (submission) => {
      const changed = structuredClone(submission) as { envelopes: Array<{ ciphertext: string }> }
      const ciphertext = changed.envelopes[0].ciphertext
      changed.envelopes[0].ciphertext = `${ciphertext.startsWith('A') ? 'B' : 'A'}${ciphertext.slice(1)}`
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
            body: JSON.stringify({ protocolVersion: 1, recipient, capability: 'AAAAAAAAAAAAAAAAAAAAAA==' }),
          })
          return { status: response.status, body: await response.text() }
        }
        return Promise.all([claim(knownRecipient), claim(unknownRecipient)])
      },
      { knownRecipient: firstAnonymousSubmission.recipient, unknownUsername: `mlsunknown${tag}` },
    )
    expect(enumerationResponses[0].status).toBe(404)
    expect(enumerationResponses[1].status).toBe(404)
    expect(enumerationResponses[0].body).toBe(enumerationResponses[1].body)

    const sentToAlice = posted(pageB, ANONYMOUS_MLS)
    const fromBob = `mls-from-bob-${tag}`
    await send(pageB, fromBob)
    expect((await requireResponseOrUiError(pageB, sentToAlice)).ok()).toBe(true)
    await expect(message(pageA, fromBob)).toBeVisible({ timeout: 90_000 })

    await reactTo(pageB, fromAlice, '❤️')
    await expect(reaction(pageA, fromAlice, '❤️')).toHaveAttribute('data-count', '1', { timeout: 45_000 })
    await reactTo(pageA, fromAlice, '❤️')
    await expect(reaction(pageB, fromAlice, '❤️')).toHaveAttribute('data-count', '2', { timeout: 45_000 })

    const groupAttachment = `mls-attachment-${tag}.txt`
    const groupAttachmentBody = `MLS encrypted attachment ${tag}`
    await sendAttachment(pageA, groupAttachment, groupAttachmentBody)
    await expect(attachmentIn(pageB, groupAttachment)).toBeVisible({ timeout: 90_000 })
    expect(await downloadAttachment(pageB, groupAttachment)).toBe(groupAttachmentBody)

    await pageB.reload()
    await expect(message(pageB, fromAlice)).toBeVisible({ timeout: 90_000 })
    await expect(message(pageB, fromBob)).toBeVisible({ timeout: 90_000 })
    const editedFromBob = `mls-edited-from-bob-${tag}`
    await editMessage(pageB, fromBob, editedFromBob)
    await expect(message(pageA, editedFromBob)).toBeVisible({ timeout: 45_000 })
    await expect(message(pageA, editedFromBob).getByTestId('chat-message-edited')).toBeVisible()
    await openSettings(pageB, 'Storage')
    await expect(pageB.getByTestId('chat-storage-summary')).toBeVisible({ timeout: 45_000 })
    await expect(pageB.getByRole('button', { name: `Clear stored Chat media for ${groupName}` })).toBeVisible()
    await openGroup(pageB, conversationId)
    expect(await downloadAttachment(pageB, groupAttachment)).toBe(groupAttachmentBody)
    recordSafeCheckpoint('two-server-mls', 'anonymous-media-completed', { media: 1 })

    // A fresh Alice install owns independent MLS credentials and leaf secrets.
    // The existing Alice device commits a manifest-bound DeviceSync Welcome;
    // the new device verifies the complete signed control history, joins
    // without an invitation decision, and survives a browser restart.
    const contextA2 = await browser.newContext()
    await signIn(contextA2, alice)
    const pageA2 = await openChat(contextA2, 'primary', watchErrors)
    const bobCapabilityEpochs: number[] = []
    pageB.on('response', (response) => {
      const path = new URL(response.url()).pathname
      if (!response.ok() || response.request().method() !== 'PUT' || path !== '/api/chat/mls/delivery-capability') return
      try {
        const publication = response.request().postDataJSON() as { conversationId?: unknown; epoch?: unknown }
        if (publication.conversationId === conversationId && typeof publication.epoch === 'number' && Number.isSafeInteger(publication.epoch)) {
          bobCapabilityEpochs.push(publication.epoch)
        }
      } catch {
        // A malformed publication is independently rejected by the server.
      }
    })
    const linkedDeviceCommit = posted(pageA, CONTROL)
    await pageA.reload()
    const linkedDeviceCommitResponse = await requireResponseOrUiError(pageA, linkedDeviceCommit)
    expect(linkedDeviceCommitResponse.ok()).toBe(true)
    const linkedDeviceCommitBody = (await linkedDeviceCommitResponse.json()) as { epoch?: unknown }
    expect(linkedDeviceCommitBody.epoch).toEqual(expect.any(Number))
    const linkedDeviceEpoch = linkedDeviceCommitBody.epoch as number
    await expect(pageA2.getByTestId(`chat-group-${conversationId}`)).toBeVisible({ timeout: 90_000 })
    await openSettings(pageA2, 'Storage')
    await expect(pageA2.getByTestId('chat-storage-summary')).toBeVisible({ timeout: 45_000 })
    await expect(pageA2.getByRole('button', { name: `Clear stored Chat media for ${groupName}` })).toBeVisible()
    await expect.poll(() => bobCapabilityEpochs.includes(linkedDeviceEpoch), { timeout: 90_000 }).toBe(true)

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

    await openGroup(pageA2, conversationId)
    const linkedSendResponse = posted(pageA2, ANONYMOUS_MLS)
    const fromAliceLinked = `mls-from-alice-linked-${tag}`
    await send(pageA2, fromAliceLinked)
    expect((await requireResponseOrUiError(pageA2, linkedSendResponse)).ok()).toBe(true)
    await expect(message(pageB, fromAliceLinked)).toBeVisible({ timeout: 90_000 })

    const toAliceLinkedResponse = posted(pageB, ANONYMOUS_MLS)
    const toAliceLinked = `mls-to-alice-linked-${tag}`
    await send(pageB, toAliceLinked)
    expect((await requireResponseOrUiError(pageB, toAliceLinkedResponse)).ok()).toBe(true)
    await expect(message(pageA2, toAliceLinked)).toBeVisible({ timeout: 90_000 })
    await pageA2.reload()
    await expect(message(pageA2, fromAliceLinked)).toBeVisible({ timeout: 90_000 })
    await expect(message(pageA2, toAliceLinked)).toBeVisible({ timeout: 90_000 })
    recordSafeCheckpoint('two-server-mls', 'linked-device-completed', { devices: 2 })

    // Re-promoting the previously demoted owner reuses the exact durable
    // group-scoped candidate key. The resulting q=2 owner set first proves
    // restart-safe incarnation recovery without an ordering vote, then closes
    // the recovered incarnation through the ordinary control quorum.
    const repromoteOwnerCommit = posted(pageA, CONTROL)
    await openMembers(pageA)
    await pageA.getByTestId(`chat-group-owner-${bobAddress}`).click()
    expect((await requireResponseOrUiError(pageA, repromoteOwnerCommit)).ok()).toBe(true)
    await expect(pageA.getByTestId(`chat-group-member-owner-${bobAddress}`)).toBeVisible({ timeout: 90_000 })
    await closeDetails(pageA)

    await openMembers(pageB)
    await expect(pageB.getByTestId(`chat-group-member-owner-${bobAddress}`)).toBeVisible({ timeout: 90_000 })
    await closeDetails(pageB)

    // Private group policy uses the same exact owner-only approval exchange.
    // The policy value stays in MLS; ordering sees only an unchanged-roster
    // transition. Restart both owners before approval to prove durable resume.
    let senderPolicyControlSubmitted = false
    let awaitingSenderPolicyApproval = true
    pageA.on('request', (request) => {
      if (awaitingSenderPolicyApproval && request.method() === 'POST' && new URL(request.url()).pathname === CONTROL) {
        senderPolicyControlSubmitted = true
      }
    })
    const senderPolicyApprovalRequest = posted(pageA, ANONYMOUS_MLS)
    await openMembers(pageA)
    await pageA.getByTestId('chat-group-senders-administrators').click()
    expect((await requireResponseOrUiError(pageA, senderPolicyApprovalRequest)).ok()).toBe(true)
    await pageA.waitForTimeout(1_000)
    expect(senderPolicyControlSubmitted).toBe(false)
    await reloadInto(pageA, conversationId)

    await openMembers(pageB)
    await expect(pageB.getByText('Approve who may send?')).toBeVisible({ timeout: 90_000 })
    await reloadInto(pageB, conversationId)
    await openMembers(pageB)
    await expect(pageB.getByText('Approve who may send?')).toBeVisible({ timeout: 90_000 })

    const senderPolicyApprovalResponse = posted(pageB, ANONYMOUS_MLS)
    const senderPolicyCommit = posted(pageA, CONTROL)
    await pageB.getByTestId('chat-group-owner-approve').click()
    expect((await requireResponseOrUiError(pageB, senderPolicyApprovalResponse)).ok()).toBe(true)
    awaitingSenderPolicyApproval = false
    expect((await requireResponseOrUiError(pageA, senderPolicyCommit)).ok()).toBe(true)
    await closeDetails(pageB)

    await openMembers(pageA)
    await expect(pageA.getByTestId('chat-group-senders-administrators')).toBeDisabled({ timeout: 90_000 })
    await closeDetails(pageA)
    // The orderer acknowledgement only proves that Alice finalized the block.
    // Wait until the remote owner has independently applied that epoch and
    // published its epoch-bound delivery capability before sending the next
    // owner-approval request.
    await openMembers(pageB)
    await expect(pageB.getByTestId('chat-group-senders-administrators')).toBeDisabled({ timeout: 90_000 })
    await closeDetails(pageB)
    await openGroup(pageC, conversationId)
    await expect(pageC.getByText('Only administrators can send messages in this group.')).toBeVisible({ timeout: 90_000 })
    await expect(composer(pageC)).toHaveCount(0)

    // V1 cryptographic policy is monotonic: owners may tighten the canonical
    // application plaintext ceiling but cannot alter suite/padding/delivery.
    const cryptographicPolicyApprovalRequest = posted(pageA, ANONYMOUS_MLS)
    await openMembers(pageA)
    await pageA.getByTestId('chat-group-maximum-plaintext').fill('1024')
    await pageA.getByTestId('chat-group-tighten-plaintext').click()
    expect((await requireResponseOrUiError(pageA, cryptographicPolicyApprovalRequest)).ok()).toBe(true)
    await closeDetails(pageA)

    await openMembers(pageB)
    await expect(pageB.getByText('Approve a smaller message limit?')).toBeVisible({ timeout: 90_000 })
    const cryptographicPolicyApprovalResponse = posted(pageB, ANONYMOUS_MLS)
    const cryptographicPolicyCommit = posted(pageA, CONTROL)
    await pageB.getByTestId('chat-group-owner-approve').click()
    expect((await requireResponseOrUiError(pageB, cryptographicPolicyApprovalResponse)).ok()).toBe(true)
    expect((await requireResponseOrUiError(pageA, cryptographicPolicyCommit)).ok()).toBe(true)
    await closeDetails(pageB)

    await openMembers(pageA)
    await expect(pageA.getByTestId('chat-group-maximum-plaintext')).toHaveValue('1024', { timeout: 90_000 })
    await closeDetails(pageA)
    // An over-limit draft is refused before anything is encrypted or sent.
    // Typing indicators travel the same anonymous path, so they are paused
    // here: any application POST would then be the refused message itself.
    await openSettings(pageA, 'Privacy')
    await pageA.getByTestId('chat-typing-indicators-toggle').uncheck()
    await openGroup(pageA, conversationId)
    let oversizedSubmitted = false
    const observeOversized = (request: Request) => {
      if (request.method() === 'POST' && new URL(request.url()).pathname === ANONYMOUS_MLS) oversizedSubmitted = true
    }
    pageA.on('request', observeOversized)
    await composer(pageA).fill('x'.repeat(2048))
    await expect(composer(pageA)).toHaveAttribute('aria-invalid', 'true')
    await expect(pageA.getByRole('button', { name: 'Send', exact: true })).toBeDisabled()
    await composer(pageA).press('Enter')
    await pageA.waitForTimeout(1_000)
    expect(oversizedSubmitted).toBe(false)
    pageA.off('request', observeOversized)
    await composer(pageA).fill('')
    await openSettings(pageA, 'Privacy')
    await pageA.getByTestId('chat-typing-indicators-toggle').check()
    await openGroup(pageA, conversationId)

    // Group-control traffic remains available under administrator-only
    // application policy. Bob removes the non-administrator before recovery.
    const administratorRemoveCommit = posted(pageB, CONTROL)
    await openMembers(pageB)
    await pageB.getByTestId(`chat-group-member-${charlieAddress}`).getByRole('button', { name: /^Remove .* from the group$/ }).click()
    expect((await requireResponseOrUiError(pageB, administratorRemoveCommit)).ok()).toBe(true)
    await expect(pageB.getByTestId(`chat-group-member-${charlieAddress}`)).toHaveCount(0, { timeout: 90_000 })
    await closeDetails(pageB)

    await openMembers(pageA)
    await expect(pageA.getByTestId(`chat-group-member-${charlieAddress}`)).toHaveCount(0, { timeout: 90_000 })
    await closeDetails(pageA)

    let recoverySubmitted = false
    let awaitingRecoveryApproval = true
    pageA.on('request', (request) => {
      if (awaitingRecoveryApproval && request.method() === 'POST' && new URL(request.url()).pathname === '/api/chat/mls/conversations/recover') {
        recoverySubmitted = true
      }
    })
    const recoveryApprovalRequest = posted(pageA, ANONYMOUS_MLS)
    await openMembers(pageA)
    await pageA.getByTestId('chat-group-recover').click()
    await confirmAction(pageA, 'Recover group')
    expect((await requireResponseOrUiError(pageA, recoveryApprovalRequest)).ok()).toBe(true)
    await pageA.waitForTimeout(1_000)
    expect(recoverySubmitted).toBe(false)
    await reloadInto(pageA, conversationId)

    await openMembers(pageB)
    await expect(pageB.getByText('Approve recovering this group?')).toBeVisible({ timeout: 90_000 })
    await reloadInto(pageB, conversationId)
    await openMembers(pageB)
    await expect(pageB.getByText('Approve recovering this group?')).toBeVisible({ timeout: 90_000 })

    const recoveryApprovalResponse = posted(pageB, ANONYMOUS_MLS)
    const recoveryCommit = posted(pageA, '/api/chat/mls/conversations/recover')
    const destinationRecoveryEvidence = pageB.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'GET' && path === `/api/chat/mls/conversations/${conversationId}/2/recovery`
    })
    await pageB.getByTestId('chat-group-owner-approve').click()
    expect((await requireResponseOrUiError(pageB, recoveryApprovalResponse)).ok()).toBe(true)
    awaitingRecoveryApproval = false
    const recoveryResponse = await requireResponseOrUiError(pageA, recoveryCommit)
    expect(recoveryResponse.ok()).toBe(true)
    expect(await recoveryResponse.json()).toMatchObject({ conversationId, previousIncarnation: 1, incarnation: 2, status: 'active' })
    expect((await destinationRecoveryEvidence).ok()).toBe(true)
    await closeDetails(pageB)

    const afterRecoverySend = posted(pageA, ANONYMOUS_MLS)
    const afterRecovery = `mls-after-recovery-${tag}`
    await send(pageA, afterRecovery)
    expect((await requireResponseOrUiError(pageA, afterRecoverySend)).ok()).toBe(true)
    await expect(message(pageB, afterRecovery)).toBeVisible({ timeout: 90_000 })

    await reloadInto(pageA, conversationId)
    await reloadInto(pageB, conversationId)
    await expect(message(pageA, afterRecovery)).toBeVisible({ timeout: 90_000 })
    await expect(message(pageB, afterRecovery)).toBeVisible({ timeout: 90_000 })

    let closeControlSubmitted = false
    let awaitingCloseApproval = true
    pageA.on('request', (request) => {
      if (awaitingCloseApproval && request.method() === 'POST' && new URL(request.url()).pathname === CONTROL) closeControlSubmitted = true
    })
    const closeApprovalRequest = posted(pageA, ANONYMOUS_MLS)
    await openMembers(pageA)
    await pageA.getByTestId('chat-group-close').click()
    await confirmAction(pageA, 'Close group')
    expect((await requireResponseOrUiError(pageA, closeApprovalRequest)).ok()).toBe(true)
    await pageA.waitForTimeout(1_000)
    expect(closeControlSubmitted).toBe(false)
    await reloadInto(pageA, conversationId)

    await openMembers(pageB)
    await expect(pageB.getByText('Approve closing this group?')).toBeVisible({ timeout: 90_000 })
    await reloadInto(pageB, conversationId)
    await openMembers(pageB)
    await expect(pageB.getByText('Approve closing this group?')).toBeVisible({ timeout: 90_000 })

    const closeApprovalResponse = posted(pageB, ANONYMOUS_MLS)
    const closeCommit = posted(pageA, CONTROL)
    await pageB.getByTestId('chat-group-owner-approve').click()
    expect((await requireResponseOrUiError(pageB, closeApprovalResponse)).ok()).toBe(true)
    awaitingCloseApproval = false
    expect((await requireResponseOrUiError(pageA, closeCommit)).ok()).toBe(true)

    const closedNotice = 'This group was closed. Its history stays, but nothing new can be sent.'
    await expect(pageA.getByText(closedNotice)).toBeVisible({ timeout: 90_000 })
    await openMembers(pageA)
    await expect(pageA.getByTestId('chat-group-closed')).toBeVisible({ timeout: 90_000 })
    await expect(pageB.getByTestId('chat-group-closed')).toBeVisible({ timeout: 90_000 })
    await closeDetails(pageA)
    await closeDetails(pageB)
    await expect(composer(pageA)).toHaveCount(0)
    await expect(composer(pageB)).toHaveCount(0)

    await reloadInto(pageA, conversationId)
    await reloadInto(pageB, conversationId)
    await expect(pageA.getByText(closedNotice)).toBeVisible({ timeout: 90_000 })
    await expect(pageB.getByText(closedNotice)).toBeVisible({ timeout: 90_000 })
    await expect(composer(pageA)).toHaveCount(0)
    await expect(composer(pageB)).toHaveCount(0)

    expectNoPageErrors(pageA, pageA2, pageB, pageC, pageD)
    await contextA.close()
    await contextA2.close()
    await contextB.close()
    await contextC.close()
    await contextD.close()
  })
})
