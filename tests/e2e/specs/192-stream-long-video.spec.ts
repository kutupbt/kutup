// Streaming a long video by block (docs/plans/drive-block-format.md §4, §9):
// a two-hour, low-bitrate WebM (made with ffmpeg here; Playwright's
// Chromium plays VP8, not H.264) uploaded to Photos, played in Photos'
// viewer and on Drive's file page. A seek to 1:30:00 plays within seconds,
// and the network log shows the reader fetched only the blocks it needed: the
// header, the trailer and manifest, the blocks around each position and the
// WebM's cues at the end, never the whole file. A song plays from Drive's
// file page the same way. With service workers blocked the players fall back
// to a whole download into a Blob.
//
// Needs ffmpeg with libvpx on the PATH; skipped without it.
import { execFileSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { expect, test, type BrowserContext, type Locator, type Page, type Request } from '@playwright/test'
import { appUrl, newAccount, registerAccount, signIn } from '../fixtures/apps'
import { item, openItem, waitForFilePage } from '../fixtures/drive'
import { wav } from '../fixtures/stream'

const PASSWORD = 'Deneme123*StreamLongVideoPassword'
const NAME = 'long.webm'
const DURATION_S = 2 * 60 * 60
const SEEK_TO_S = 90 * 60
const BLOCK = 4 * 1024 * 1024

function hasFfmpeg(): boolean {
  try {
    return execFileSync('ffmpeg', ['-hide_banner', '-encoders'], { stdio: 'pipe' }).toString().includes('libvpx')
  } catch {
    return false
  }
}

/** Two hours of a moving test card at 4 fps, about 160 kbit/s: a few hundred MB. */
function longVideo(): Buffer {
  const dir = mkdtempSync(join(tmpdir(), 'kutup-192-'))
  try {
    const out = join(dir, NAME)
    execFileSync(
      'ffmpeg',
      ['-hide_banner', '-loglevel', 'error', '-f', 'lavfi', '-i', `testsrc=size=320x180:rate=4:duration=${DURATION_S}`,
        '-c:v', 'libvpx', '-b:v', '160k', '-deadline', 'realtime', '-cpu-used', '8', '-g', '40', '-an', out],
      { stdio: 'pipe', timeout: 15 * 60_000 },
    )
    return readFileSync(out)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
}

/** The reader's ranged reads of stored objects (from its Worker), and what came back. */
function rangeLog(context: BrowserContext) {
  const reads: { url: string; start: number; end: number }[] = []
  const onRequest = async (request: Request) => {
    const range = (await request.allHeaders())['range']
    if (!range || !new URL(request.url()).pathname.startsWith('/api/')) return
    const response = await request.response()
    const match = /^bytes (\d+)-(\d+)\/\d+$/.exec(response?.headers()['content-range'] ?? '')
    if (match) reads.push({ url: request.url(), start: Number(match[1]), end: Number(match[2]) })
  }
  context.on('requestfinished', (request) => void onRequest(request))
  return {
    reads,
    /** Distinct blocks touched since `from` (an index into `reads`). */
    blocksSince(from: number): Set<number> {
      const blocks = new Set<number>()
      for (const read of reads.slice(from)) {
        for (let block = Math.floor(read.start / BLOCK); block <= Math.floor(read.end / BLOCK); block++) blocks.add(block)
      }
      return blocks
    },
    bytesSince(from: number): number {
      return reads.slice(from).reduce((sum, read) => sum + read.end - read.start + 1, 0)
    },
  }
}

async function startMuted(media: Locator): Promise<void> {
  await media.evaluate(async (element: HTMLMediaElement) => {
    element.muted = true
    await element.play()
  })
}

async function seekAndPlay(media: Locator, seconds: number): Promise<void> {
  await media.evaluate((element: HTMLMediaElement, at: number) => {
    element.currentTime = at
  }, seconds)
  // Within a few seconds of the seek, playback is past it.
  await expect.poll(() => media.evaluate((element: HTMLMediaElement) => element.currentTime), { timeout: 20_000 }).toBeGreaterThan(seconds + 1)
}

async function uploadToPhotos(page: Page, video: Buffer): Promise<void> {
  await page.goto(appUrl('photos'))
  const upload = page.getByRole('button', { name: 'Upload', exact: true }).first()
  await expect(upload).toBeVisible({ timeout: 120_000 })
  const [chooser] = await Promise.all([page.waitForEvent('filechooser'), upload.click()])
  await chooser.setFiles({ name: NAME, mimeType: 'video/webm', buffer: video })
  await expect(page.getByText('Uploads complete')).toBeVisible({ timeout: 10 * 60_000 })
}

test.describe('a long video streams by block', () => {
  test.skip(!hasFfmpeg(), 'needs ffmpeg with libvpx to make the two-hour video')

  test('Photos and Drive play it, a seek to 1:30:00 fetches only the blocks it needs', async ({ browser }) => {
    test.setTimeout(30 * 60_000)
    const video = longVideo()
    expect(video.length).toBeGreaterThan(50 * BLOCK)
    const context = await browser.newContext()
    await registerAccount(context, newAccount('longvid', PASSWORD))
    const log = rangeLog(context)
    const page = await context.newPage()
    await uploadToPhotos(page, video)

    // Photos' viewer.
    await page.getByRole('button', { name: new RegExp(`^${NAME.replace('.', '\\.')},`) }).click()
    const inPhotos = page.locator('video')
    await expect(inPhotos).toBeVisible({ timeout: 60_000 })
    expect(await inPhotos.getAttribute('src')).toMatch(/^\/sw\/stream\/[A-Za-z0-9_-]{22}$/)
    await startMuted(inPhotos)
    const beforeSeek = log.reads.length
    await seekAndPlay(inPhotos, SEEK_TO_S)
    // The block under 1:30:00 and the one read ahead, perhaps the next: a handful, not the file.
    expect(log.blocksSince(beforeSeek).size).toBeLessThanOrEqual(4)
    // From the first byte to here: the header, the manifest, the start, the cues and the seek.
    expect(log.bytesSince(0)).toBeLessThan(12 * BLOCK)
    expect(log.bytesSince(0)).toBeLessThan(video.length / 4)
    await page.keyboard.press('Escape')

    // Drive's file page: the same file, from the Photos folder.
    await page.goto(appUrl('drive'))
    await expect(page.getByRole('button', { name: 'New' }).first()).toBeVisible({ timeout: 120_000 })
    await openItem(page, 'Photos')
    await expect(item(page, NAME)).toBeVisible({ timeout: 60_000 })
    const beforeDrive = log.reads.length
    await openItem(page, NAME)
    await waitForFilePage(page, 'drive')
    const inDrive = page.locator('video')
    await expect(inDrive).toBeVisible({ timeout: 60_000 })
    expect(await inDrive.getAttribute('src')).toMatch(/^\/sw\/stream\//)
    await startMuted(inDrive)
    const beforeDriveSeek = log.reads.length
    await seekAndPlay(inDrive, SEEK_TO_S + 600)
    expect(log.blocksSince(beforeDriveSeek).size).toBeLessThanOrEqual(4)
    expect(log.bytesSince(beforeDrive)).toBeLessThan(12 * BLOCK)
    await context.close()
  })
})

test('a song plays from Drive’s file page, and without a service worker from a Blob', async ({ browser }) => {
  test.slow()
  const account = newAccount('songpage', PASSWORD)
  const context = await browser.newContext()
  await registerAccount(context, account)
  const page = await context.newPage()
  await page.goto(appUrl('drive'))
  await expect(page.getByRole('button', { name: 'New' }).first()).toBeVisible({ timeout: 120_000 })
  await page.getByRole('button', { name: 'New' }).first().click()
  const [chooser] = await Promise.all([page.waitForEvent('filechooser'), page.getByRole('menuitem', { name: 'Upload files' }).click()])
  await chooser.setFiles({ name: 'song.wav', mimeType: 'audio/wav', buffer: wav(60) })
  await expect(item(page, 'song.wav')).toBeVisible({ timeout: 120_000 })
  await openItem(page, 'song.wav')
  await waitForFilePage(page, 'drive')
  const audio = page.locator('audio')
  await expect(audio).toBeVisible({ timeout: 60_000 })
  expect(await audio.getAttribute('src')).toMatch(/^\/sw\/stream\//)
  await startMuted(audio)
  await seekAndPlay(audio, 40)
  const fileUrl = page.url()
  await context.close()

  // No service worker (a private window, workers turned off): after the
  // page gives up waiting for one, the whole file into a Blob.
  const blocked = await browser.newContext({ serviceWorkers: 'block' })
  await signIn(blocked, account)
  const again = await blocked.newPage()
  await again.goto(fileUrl)
  const fallback = again.locator('audio')
  await expect(fallback).toBeVisible({ timeout: 90_000 })
  expect(await fallback.getAttribute('src')).toMatch(/^blob:/)
  await startMuted(fallback)
  await seekAndPlay(fallback, 40)
  await blocked.close()
})
