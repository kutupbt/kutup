// Media streamed through Kutup's service worker
// (docs/plans/drive-block-format.md §4): a long WAV made here (no ffmpeg
// needed: Chromium plays PCM), uploaded to Drive and played in Quick Look,
// and what the player's ranged requests got back.
import { expect, type BrowserContext, type Page, type Response } from '@playwright/test'
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

/** Opens `name` in Quick Look and starts it playing (muted, so no gesture is needed); waits for the first stream answer. */
export async function playInQuickLook(page: Page, name: string): Promise<void> {
  const first = page.waitForResponse(isStreamAnswer, { timeout: 60_000 })
  await itemAction(page, name, 'Quick look')
  const audio = page.locator('audio')
  await expect(audio).toBeVisible({ timeout: 60_000 })
  expect(await audio.getAttribute('src')).toMatch(/^\/sw\/stream\/[A-Za-z0-9_-]{22}$/)
  await first
  await audio.evaluate(async (element: HTMLAudioElement) => {
    element.muted = true
    await element.play()
  })
}

/** Seeks to `seconds` and waits until playback is past it, through a new ranged answer. */
export async function seekAndPlay(page: Page, seconds: number): Promise<void> {
  const answered = page.waitForResponse(isStreamAnswer, { timeout: 60_000 })
  await page.locator('audio').evaluate((element: HTMLAudioElement, at: number) => {
    element.currentTime = at
  }, seconds)
  const response = await answered
  expect(response.headers()['content-range']).toMatch(/^bytes \d+-\d+\/\d+$/)
  await expect
    .poll(() => page.locator('audio').evaluate((element: HTMLAudioElement) => element.currentTime), { timeout: 30_000 })
    .toBeGreaterThan(seconds + 1)
}
