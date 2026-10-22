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
  openConversationWith,
  openDetails,
  openDirectChat,
  openNoteToSelf,
  openSettings,
  reactTo,
  reaction,
  replyTo,
  send,
  sendAttachment,
  setDisappearing,
} from '../fixtures/chat'

/** An identified (not sealed) Direct send: POST /api/chat/accounts/<id>/messages. */
const IDENTIFIED_SEND = /^\/api\/chat\/accounts\/[0-9a-f-]{36}\/messages$/
/** A sealed send: POST /api/chat/anonymous/accounts/<id>/messages. */
const ANONYMOUS_SEND = /^\/api\/chat\/anonymous\/accounts\/[0-9a-f-]{36}\/messages$/
/** A sealed bundle fetch or send: POST /api/chat/anonymous/accounts/<id>/{keys,messages}. */
const ANONYMOUS_KEYS_OR_SEND = /^\/api\/chat\/anonymous\/accounts\/[0-9a-f-]{36}\/(keys|messages)$/

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
 * The Rust/WASM runtimes live in directories named for their content hash,
 * so a deployment never pairs an old Rust ABI with a new page: the URLs the
 * page loaded must be hashed, and may then be cached for good.
 */
async function expectWasmRuntimeCaching(page: Page): Promise<void> {
  const urls = await page.evaluate(() =>
    performance
      .getEntriesByType('resource')
      .map((entry) => new URL(entry.name).pathname)
      .filter((path) => /^\/(chat|crypto)-wasm\//.test(path)),
  )
  for (const module of ['chat', 'crypto']) {
    const loaded = urls.filter((path) => path.startsWith(`/${module}-wasm/`))
    expect(loaded.length, `${module} runtime must be loaded`).toBeGreaterThan(0)
    for (const path of loaded) {
      expect(path, `${path} must be in a content-hashed directory`).toMatch(/^\/(chat|crypto)-wasm\/[0-9a-f]{16}\//)
      const response = await page.evaluate(async (url) => {
        const result = await fetch(url, { method: 'HEAD', cache: 'no-store' })
        return { ok: result.ok, cacheControl: result.headers.get('cache-control') ?? '' }
      }, path)
      expect(response.ok, `${path} must be deployed with the page`).toBe(true)
      expect(response.cacheControl, `${path} is cached for good`).toContain('immutable')
    }
  }
}

function posted(page: Page, pathname: string | RegExp): Promise<Response> {
  // Control blocks wait for an ordering quorum, which the client retries
  // for a while when one server lags a block behind.
  return page.waitForResponse((response) => {
    const path = new URL(response.url()).pathname
    return response.request().method() === 'POST' && (typeof pathname === 'string' ? path === pathname : pathname.test(path))
  }, { timeout: 60_000 })
}

const CONTROL = '/api/chat/mls/control/blocks'
const ANONYMOUS_MLS = '/api/chat/mls/anonymous/messages'

/** The anonymous MLS submission for a recipient on `server`. One group send
 * posts one submission per recipient, and they may answer in any order. */
function postedAnonymousTo(page: Page, server: string): Promise<Response> {
  return page.waitForResponse((response) => {
    const request = response.request()
    if (request.method() !== 'POST' || new URL(response.url()).pathname !== ANONYMOUS_MLS) return false
    const submission = request.postDataJSON() as { recipient?: { server?: string } } | null
    return submission?.recipient?.server === server
  }, { timeout: 60_000 })
}

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
  // Settles only when an error toast actually shows; the response wait has
  // its own timeout.
  const errorText = uiError
    .waitFor({ state: 'visible', timeout: 90_000 })
    .then(async () => (await uiError.textContent())?.trim() || 'unknown error')
    .catch(() => new Promise<never>(() => {}))
  const first = await Promise.race([
    response.then((value) => ({ kind: 'response' as const, value })),
    errorText.then((value) => ({ kind: 'error' as const, value })),
  ])
  if (first.kind === 'error') throw new Error(`browser operation failed: ${first.value ?? 'unknown error'}`)
  const lateError = await Promise.race([errorText, page.waitForTimeout(1_000).then(() => undefined)])
  if (lateError) throw new Error(`browser operation failed: ${lateError}`)
  return first.value
}


/** Confirms a destructive group action in its alert dialog. */
async function confirmAction(page: Page, submit: string): Promise<void> {
  await page.getByRole('alertdialog').getByRole('button', { name: submit, exact: true }).click()
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

    // An installation re-registers (the account's first Chat device, its
    // manifest in the registration), then its manifest update never reaches
    // the server. A request that fails to connect is the server being out of
    // reach: Chat says so and keeps retrying, and offers no repair.
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
    await expect(abandonedPageA.getByText("The server can't be reached").first()).toBeVisible({ timeout: 90_000 })
    await expect(abandonedPageA.getByRole('button', { name: 'Repair this browser' })).toHaveCount(0)
    expect(interruptedManifestAttempts).toBeGreaterThan(0)
    await abandonedContextA.close()

    // A different installation, with the abandoned one gone, starts Alice's
    // Chat over: its re-registration drops the abandoned device.
    const contextA = await browser.newContext()
    await signIn(contextA, alice)
    const pageA = await openChat(contextA, 'primary', watchErrors)
    const pageB = await openChat(contextB, 'secondary', watchErrors)
    await enableReadReceipts(pageB)
    await expectWasmRuntimeCaching(pageA)
    await expectWasmRuntimeCaching(pageB)

    const identifiedToBob: string[] = []
    pageA.on('request', (request) => {
      const path = new URL(request.url()).pathname
      if (request.method() === 'POST' && IDENTIFIED_SEND.test(path)) identifiedToBob.push(path)
    })

    await openDirectChat(pageA, bobAddress)
    // V1 does not allocate destination media for a message request. Direct
    // attachments become available only after the contact is accepted.
    await expect(pageA.getByTestId('chat-attachment-button')).toHaveCount(0)
    await expect(pageA.getByTestId('chat-attachment-input')).toHaveCount(0)
    await expect(pageA.getByTestId('chat-voice-button')).toHaveCount(0)
    const firstIdentified = posted(pageA, IDENTIFIED_SEND)
    const first = `identified-first-${tag}`
    await send(pageA, first)
    expect((await firstIdentified).ok()).toBe(true)
    // The watch below is armed: it saw this identified send.
    expect(identifiedToBob.length).toBeGreaterThan(0)
    await openConversationWith(pageB, alice.username)
    await expect(message(pageB, first)).toBeVisible({ timeout: 45_000 })
    await acceptRequest(pageB)

    // The server can distribute signed manifests but cannot promote trust.
    // Both installations independently derive the same full pair/key binding;
    // only an exact face-to-face QR exchange turns the gray shields green.
    await openDetails(pageA)
    await pageA.getByTestId('chat-safety-open').click()
    const safetyA = pageA.getByRole('dialog')
    // Signal's safety number (libsignal Fingerprint v2 over the account
    // identities, QR `kutup://verify/v4/`): both sides show the same twelve
    // groups of five digits; each side's QR carries its own half first, so
    // each scans the other's code.
    const qrA = await safetyA.getByTestId('chat-safety-qr').getAttribute('data-value')
    expect(qrA).toMatch(/^kutup:\/\/verify\/v4\/[A-Za-z0-9_-]+$/)
    const numberA = (await safetyA.getByTestId('chat-safety-number').textContent())?.trim()
    expect(numberA).toMatch(/^\d{5}( \d{5}){11}$/)
    await openDetails(pageB)
    await pageB.getByTestId('chat-safety-open').click()
    const safetyB = pageB.getByRole('dialog')
    const qrB = await safetyB.getByTestId('chat-safety-qr').getAttribute('data-value')
    expect(qrB).toMatch(/^kutup:\/\/verify\/v4\/[A-Za-z0-9_-]+$/)
    expect(qrB).not.toBe(qrA)
    await expect(safetyB.getByTestId('chat-safety-number')).toHaveText(numberA!)
    // A side's own code is not a match: only the other side's is.
    await safetyB.getByPlaceholder('kutup://verify/v4/…').fill(qrB!)
    await safetyB.getByRole('button', { name: 'Verify exact match' }).click()
    await expect(pageB.getByText('That QR code does not match this conversation. Nothing was verified.')).toBeVisible()
    await expect(safetyB.getByText('Verified face to face on this device.')).toHaveCount(0)
    await safetyB.getByPlaceholder('kutup://verify/v4/…').fill(qrA!)
    await safetyB.getByRole('button', { name: 'Verify exact match' }).click()
    await expect(safetyB.getByText('Verified face to face on this device.')).toBeVisible()
    await pageB.keyboard.press('Escape')
    await closeDetails(pageB)
    await safetyA.getByPlaceholder('kutup://verify/v4/…').fill(qrB!)
    await safetyA.getByRole('button', { name: 'Verify exact match' }).click()
    await expect(safetyA.getByText('Verified face to face on this device.')).toBeVisible()
    await pageA.keyboard.press('Escape')
    await closeDetails(pageA)

    const typingDraft = `typing-only-${tag}`
    await composer(pageB).fill(typingDraft)
    await expect(pageA.getByTestId('chat-typing-indicator')).toContainText(bob.username, { timeout: 45_000 })
    await expect(pageA.getByText(typingDraft)).toHaveCount(0)

    const sealedReplyResponse = posted(pageB, ANONYMOUS_SEND)
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
    const sealedSendResponse = posted(pageA, ANONYMOUS_SEND)
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
        ANONYMOUS_KEYS_OR_SEND.test(path) &&
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
})
