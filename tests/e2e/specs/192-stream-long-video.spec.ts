// Streaming a long video by block (docs/plans/drive-block-format.md §4, §9):
// a two-hour, low-bitrate video made with ffmpeg here, uploaded to Photos,
// played in Photos' viewer and on Drive's file page. A seek to 1:30:00 plays
// within seconds, and the network log shows the reader fetched only the
// blocks it needed: the header, the trailer and manifest, the blocks around
// each position and the container's index, never the whole file. A song
// plays from Drive's file page the same way. With service workers blocked
// the players fall back to a whole download into a Blob.
//
// Chromium: a WebM (VP8; Playwright's Chromium plays no H.264), and every
// player must stream. WebKit (suites/webkit.txt): an H.264 MP4, since WebKit
// may not play WebM, and a player may stream or fall back to a Blob (some
// builds give a media element an empty `destination`, which the worker
// refuses); it must play either way, and the path it took is recorded as a
// "playback path" annotation. The block counts apply to a stream only.
//
// Needs ffmpeg on the PATH, with libvpx (Chromium) or libx264 (WebKit);
// skipped without it.
import { execFileSync } from 'node:child_process'
import { mkdtempSync, rmSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { expect, test, type BrowserContext, type Locator, type Page, type Request } from '../fixtures/test'
import { appUrl, newAccount, registerAccount, signIn } from '../fixtures/apps'
import { item, openItem, waitForFilePage } from '../fixtures/drive'
import { playingPath, wav } from '../fixtures/stream'

const PASSWORD = 'Deneme123*StreamLongVideoPassword'
const DURATION_S = 2 * 60 * 60
const SEEK_TO_S = 90 * 60
const BLOCK = 4 * 1024 * 1024
// Noise on the card, so the encoder spends its bitrate: libvpx (ffmpeg 7.1)
// made 62 MB of a still card at 320 kbit/s, under the 50-block floor.
const SOURCE = ['-hide_banner', '-loglevel', 'error', '-f', 'lavfi', '-i', `testsrc=size=320x180:rate=4:duration=${DURATION_S},noise=alls=40:allf=t`]

/** The test video for a browser: what it plays, and how ffmpeg makes it. */
interface LongVideo {
  name: string
  mimeType: string
  encoder: string
  args: string[]
}

function videoFor(browserName: string): LongVideo {
  if (browserName === 'webkit') {
    return {
      // H.264 at a constant 320 kbit/s (filler keeps x264 from undershooting a
      // still test card), the index at the front: about 290 MB.
      name: 'long.mp4',
      mimeType: 'video/mp4',
      encoder: 'libx264',
      args: ['-c:v', 'libx264', '-preset', 'ultrafast', '-pix_fmt', 'yuv420p', '-b:v', '320k', '-minrate', '320k', '-maxrate', '320k',
        '-bufsize', '640k', '-x264-params', 'nal-hrd=cbr', '-g', '40', '-movflags', '+faststart', '-an'],
    }
  }
  // VP8 at about 320 kbit/s (about 290 MB over two hours, above the 50-block floor), its cues at the end.
  return {
    name: 'long.webm',
    mimeType: 'video/webm',
    encoder: 'libvpx',
    args: ['-c:v', 'libvpx', '-b:v', '320k', '-minrate', '320k', '-maxrate', '320k', '-deadline', 'realtime', '-cpu-used', '8', '-g', '40', '-an'],
  }
}

function hasEncoder(encoder: string): boolean {
  try {
    return execFileSync('ffmpeg', ['-hide_banner', '-encoders'], { stdio: 'pipe' }).toString().includes(encoder)
  } catch {
    return false
  }
}

/**
 * Two hours of a moving, noisy test card at 4 fps, written to a file:
 * Playwright takes a file over 50 MB by its path only. `remove` deletes it.
 */
function longVideo(spec: LongVideo): { path: string; size: number; remove: () => void } {
  const dir = mkdtempSync(join(tmpdir(), 'kutup-192-'))
  const remove = () => rmSync(dir, { recursive: true, force: true })
  try {
    const path = join(dir, spec.name)
    execFileSync('ffmpeg', [...SOURCE, ...spec.args, path], { stdio: 'pipe', timeout: 15 * 60_000 })
    return { path, size: statSync(path).size, remove }
  } catch (error) {
    remove()
    throw error
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

async function seekAndPlay(media: Locator, seconds: number): Promise<void> {
  await media.evaluate((element: HTMLMediaElement, at: number) => {
    element.currentTime = at
  }, seconds)
  // Within a few seconds of the seek, playback is past it.
  await expect.poll(() => media.evaluate((element: HTMLMediaElement) => element.currentTime), { timeout: 20_000 }).toBeGreaterThan(seconds + 1)
}

async function uploadToPhotos(page: Page, video: string): Promise<void> {
  await page.goto(appUrl('photos'))
  const upload = page.getByRole('button', { name: 'Upload', exact: true }).first()
  await expect(upload).toBeVisible({ timeout: 120_000 })
  const [chooser] = await Promise.all([page.waitForEvent('filechooser'), upload.click()])
  await chooser.setFiles(video)
  await expect(page.getByText('Uploads complete')).toBeVisible({ timeout: 10 * 60_000 })
}

test.describe('a long video streams by block', () => {
  test('Photos and Drive play it, a seek to 1:30:00 fetches only the blocks it needs', async ({ browser, browserName }) => {
    const spec = videoFor(browserName)
    test.skip(!hasEncoder(spec.encoder), `needs ffmpeg with ${spec.encoder} to make the two-hour ${spec.name} for ${browserName}`)
    test.setTimeout(30 * 60_000)
    const video = longVideo(spec)
    if (video.size <= 50 * BLOCK) video.remove()
    expect(video.size, 'the video is above the 50-block floor').toBeGreaterThan(50 * BLOCK)
    const context = await browser.newContext()
    await registerAccount(context, newAccount('longvid', PASSWORD))
    const log = rangeLog(context)
    const page = await context.newPage()
    try {
      await uploadToPhotos(page, video.path)
    } finally {
      video.remove()
    }

    // Photos' viewer.
    await page.getByRole('button', { name: new RegExp(`^${spec.name.replace('.', '\\.')},`) }).click()
    const inPhotos = page.locator('video')
    await expect(inPhotos).toBeVisible({ timeout: 60_000 })
    if (browserName === 'chromium') expect(await inPhotos.getAttribute('src')).toMatch(/^\/sw\/stream\/[A-Za-z0-9_-]{22}$/)
    const inPhotosPath = await playingPath(inPhotos, `Photos' viewer ${spec.name}`, { timeout: 10 * 60_000 })
    const beforeSeek = log.reads.length
    await seekAndPlay(inPhotos, SEEK_TO_S)
    // The last block holds the WebM's cues (its index, at the end), which
    // Chromium reads at the first seek: not counted with the media read there.
    const lastBlock = Math.floor((video.size - 1) / BLOCK)
    const mediaBlocks = (from: number) => [...log.blocksSince(from)].filter((block) => block < lastBlock)
    if (inPhotosPath === 'stream') {
      // The block under 1:30:00 and those read ahead (at 320 kbit/s a block
      // is about 105 s): a handful, not the file.
      expect(mediaBlocks(beforeSeek).length).toBeLessThanOrEqual(4)
      // From the first byte to here: the header, the manifest, the start, the index and the seek.
      expect(log.bytesSince(0)).toBeLessThan(12 * BLOCK)
      expect(log.bytesSince(0)).toBeLessThan(video.size / 4)
    }
    await page.keyboard.press('Escape')

    // Drive's file page: the same file, from the Photos folder.
    await page.goto(appUrl('drive'))
    await expect(page.getByRole('button', { name: 'New' }).first()).toBeVisible({ timeout: 120_000 })
    await openItem(page, 'Photos')
    await expect(item(page, spec.name)).toBeVisible({ timeout: 60_000 })
    const beforeDrive = log.reads.length
    await openItem(page, spec.name)
    await waitForFilePage(page, 'drive')
    const inDrive = page.locator('video')
    await expect(inDrive).toBeVisible({ timeout: 60_000 })
    if (browserName === 'chromium') expect(await inDrive.getAttribute('src')).toMatch(/^\/sw\/stream\//)
    const inDrivePath = await playingPath(inDrive, `Drive's file page ${spec.name}`, { timeout: 10 * 60_000 })
    const beforeDriveSeek = log.reads.length
    await seekAndPlay(inDrive, SEEK_TO_S + 600)
    if (inDrivePath === 'stream') {
      expect(mediaBlocks(beforeDriveSeek).length).toBeLessThanOrEqual(4)
      expect(log.bytesSince(beforeDrive)).toBeLessThan(12 * BLOCK)
    }
    await context.close()
  })
})

test('a song plays from Drive’s file page, and without a service worker from a Blob', async ({ browser, browserName }) => {
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
  if (browserName === 'chromium') expect(await audio.getAttribute('src')).toMatch(/^\/sw\/stream\//)
  await playingPath(audio, 'Drive’s file page song.wav')
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
  await playingPath(fallback, 'song.wav with service workers blocked', { expected: 'fallback' })
  await seekAndPlay(fallback, 40)
  await blocked.close()
})
