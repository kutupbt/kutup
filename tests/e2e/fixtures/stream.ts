// Media streamed through Kutup's service worker
// (docs/plans/drive-block-format.md §4): a long WAV made here (no ffmpeg
// needed: Chromium and WebKit play PCM), uploaded to Drive and played in Quick Look,
// and what the player's ranged requests got back.
//
// On Chromium a player must stream. On WebKit it may instead fall back to a
// Blob (some builds give a media element an empty `destination`, which the
// worker refuses): there the helpers accept either path, assert that it
// plays, and record which one it took as a "playback path" annotation.
import { expect, test, type BrowserContext, type Locator, type Page, type Response } from '@playwright/test'
import { newAccount, openDrive, registerAccount } from './apps'
import { item, itemAction } from './drive'

const RATE = 44_100
const CHANNELS = 2

/**
 * A WAV of `seconds` of quiet tones: 176,400 bytes a second, so 60 s spans
 * three 4 MiB blocks and a seek lands in another block than the start.
 */
export function wav(seconds: number): Buffer {
  const samples = RATE * seconds
  const data = samples * CHANNELS * 2
  const out = Buffer.alloc(44 + data)
  out.write('RIFF', 0)
  out.writeUInt32LE(36 + data, 4)
  out.write('WAVE', 8)
  out.write('fmt ', 12)
  out.writeUInt32LE(16, 16)
  out.writeUInt16LE(1, 20)
  out.writeUInt16LE(CHANNELS, 22)
  out.writeUInt32LE(RATE, 24)
  out.writeUInt32LE(RATE * CHANNELS * 2, 28)
  out.writeUInt16LE(CHANNELS * 2, 32)
  out.writeUInt16LE(16, 34)
  out.write('data', 36)
  out.writeUInt32LE(data, 40)
  for (let i = 0; i < samples; i++) {
    const value = Math.round(Math.sin((2 * Math.PI * 440 * i) / RATE) * 2000)
    out.writeInt16LE(value, 44 + i * 4)
    out.writeInt16LE(value, 46 + i * 4)
  }
  return out
}

/** A new account's Drive with `name` uploaded. */
export async function driveWithSong(context: BrowserContext, prefix: string, password: string, name: string, seconds = 60): Promise<Page> {
  const account = newAccount(prefix, password)
  await registerAccount(context, account)
  const page = await openDrive(context)
  await page.getByRole('button', { name: 'New' }).first().click()
  const [chooser] = await Promise.all([page.waitForEvent('filechooser'), page.getByRole('menuitem', { name: 'Upload files' }).click()])
  await chooser.setFiles({ name, mimeType: 'audio/wav', buffer: wav(seconds) })
  await expect(item(page, name)).toBeVisible({ timeout: 120_000 })
  return page
}

/** A stream answer the service worker gave. */
export function isStreamAnswer(response: Response): boolean {
  return new URL(response.url()).pathname.startsWith('/sw/stream/') && response.status() === 206
}

/** How a player plays: through the worker's `/sw/stream/…`, or from a whole download in a Blob. */
export type PlaybackPath = 'stream' | 'fallback'

/** The browser `page` runs in: chromium, webkit or firefox. */
export function browserOf(page: Page): string {
  return page.context().browser()?.browserType().name() ?? 'chromium'
}

/**
 * Starts `media` playing (muted, so no gesture is needed) and waits until
 * it plays, from whichever source the player settled on: a stream refused
 * before its first frame is replaced by a Blob, so the element (and its
 * `src`) may change meanwhile. Returns the path it took, recorded as a
 * "playback path" annotation. It must be `expected` when given, else on
 * Chromium the stream.
 */
export async function playingPath(
  media: Locator,
  what: string,
  { timeout = 120_000, expected }: { timeout?: number; expected?: PlaybackPath } = {},
): Promise<PlaybackPath> {
  let src = ''
  await expect
    .poll(
      async () => {
        try {
          const state = await media.evaluate((element: HTMLMediaElement) => {
            element.muted = true
            if (element.paused) element.play().catch(() => {})
            return { src: element.currentSrc || element.getAttribute('src') || '', time: element.currentTime }
          })
          src = state.src
          return state.time
        } catch {
          // Replaced between the lookup and the call: the next poll finds the new one.
          return 0
        }
      },
      { timeout, intervals: [250, 500, 1_000] },
    )
    .toBeGreaterThan(0)
  const path = pathOf(src)
  const browser = browserOf(media.page())
  test.info().annotations.push({ type: 'playback path', description: `${what}: ${path} (${browser})` })
  console.log(`playback path: ${what}: ${path} (${browser})`)
  if (expected) expect(path, `${what} plays by ${expected}`).toBe(expected)
  else if (browser === 'chromium') expect(path, `${what} streams on Chromium`).toBe('stream')
  return path
}

function pathOf(src: string): PlaybackPath {
  if (src.startsWith('blob:')) return 'fallback'
  if (new URL(src, 'https://x.invalid').pathname.startsWith('/sw/stream/')) return 'stream'
  throw new Error(`a player plays neither a stream nor a Blob: ${src}`)
}

/**
 * Opens `name` in Quick Look and starts it playing; returns how it plays.
 * On Chromium: from a stream, after its first answer. Elsewhere either path,
 * and no network check: Playwright sees service-worker answers on Chromium only.
 */
export async function playInQuickLook(page: Page, name: string): Promise<PlaybackPath> {
  const chromium = browserOf(page) === 'chromium'
  const first = chromium ? page.waitForResponse(isStreamAnswer, { timeout: 60_000 }) : null
  await itemAction(page, name, 'Quick look')
  const audio = page.locator('audio')
  await expect(audio).toBeVisible({ timeout: 60_000 })
  if (chromium) {
    expect(await audio.getAttribute('src')).toMatch(/^\/sw\/stream\/[A-Za-z0-9_-]{22}$/)
    await first
  }
  return playingPath(audio, `Quick Look ${name}`)
}

/**
 * Seeks to `seconds` and waits until playback is past it. On Chromium also
 * through a new ranged answer from the worker.
 */
export async function seekAndPlay(page: Page, seconds: number): Promise<void> {
  const answered = browserOf(page) === 'chromium' ? page.waitForResponse(isStreamAnswer, { timeout: 60_000 }) : null
  await page.locator('audio').evaluate((element: HTMLAudioElement, at: number) => {
    element.currentTime = at
  }, seconds)
  if (answered) expect((await answered).headers()['content-range']).toMatch(/^bytes \d+-\d+\/\d+$/)
  await expect
    .poll(() => page.locator('audio').evaluate((element: HTMLAudioElement) => element.currentTime), { timeout: 30_000 })
    .toBeGreaterThan(seconds + 1)
}
