// Uploads that survive what takes hours on a slow line
// (docs/roadmap.md, "Drive · large uploads from the browser"):
//   1. a reload in the middle: the upload is offered again, the same file is
//      chosen, it goes on from where the server stopped, and the file that
//      arrives is byte for byte the one that was chosen;
//   2. a multi-GB file through a connection lost for longer than the old
//      ~20 s of retries, then a reload, with the page's memory bounded.
// The second size is E2E_LARGE_UPLOAD_MB (default 2048).

import { createHash } from 'node:crypto'
import { createReadStream, createWriteStream } from 'node:fs'
import { readFile, stat } from 'node:fs/promises'
import { expect, test, type Page } from '@playwright/test'
import { newAccount, openDrive, registerAccount } from '../fixtures/apps'
import { item, itemAction } from '../fixtures/drive'

const PASSWORD = 'Deneme123*ResumableUploadPassword'
const MB = 1024 * 1024

/** A file of `bytes` on disk in a deterministic pattern (its modified time stays put). */
async function writeFile(path: string, bytes: number): Promise<void> {
  const block = Buffer.alloc(MB)
  for (let i = 0; i < MB; i++) block[i] = (i * 31 + 7) & 0xff
  const out = createWriteStream(path)
  for (let written = 0; written < bytes; written += MB) {
    const piece = written + MB <= bytes ? block : block.subarray(0, bytes - written)
    // A different first byte in every megabyte: no two chunks alike.
    piece[0] = (written / MB) & 0xff
    if (!out.write(piece)) await new Promise((resolve) => out.once('drain', resolve))
  }
  await new Promise<void>((resolve, reject) => out.end((error?: Error | null) => (error ? reject(error) : resolve())))
}

async function sha256(path: string): Promise<string> {
  const hash = createHash('sha256')
  for await (const chunk of createReadStream(path)) hash.update(chunk as Buffer)
  return hash.digest('hex')
}

function progressOf(page: Page, name: string) {
  return page.getByRole('progressbar', { name })
}

async function percent(page: Page, name: string): Promise<number> {
  const value = await progressOf(page, name).getAttribute('aria-valuenow').catch(() => null)
  return value === null ? -1 : Number(value)
}

async function startUpload(page: Page, path: string) {
  await page.getByRole('button', { name: 'New' }).first().click()
  const [chooser] = await Promise.all([page.waitForEvent('filechooser'), page.getByRole('menuitem', { name: 'Upload files' }).click()])
  await chooser.setFiles(path)
}

async function resumeFromPanel(page: Page, name: string, path: string) {
  const panel = page.getByRole('region', { name: 'Interrupted uploads' })
  await expect(panel.getByText(name, { exact: true })).toBeVisible({ timeout: 60_000 })
  const [chooser] = await Promise.all([page.waitForEvent('filechooser'), panel.getByRole('button', { name: `Resume ${name}` }).click()])
  await chooser.setFiles(path)
}

/** The page's JavaScript heap in MB, from Chromium. */
async function heapMb(page: Page): Promise<number> {
  const cdp = await page.context().newCDPSession(page)
  await cdp.send('Performance.enable')
  const { metrics } = await cdp.send('Performance.getMetrics')
  await cdp.detach()
  return (metrics.find((m) => m.name === 'JSHeapUsedSize')?.value ?? 0) / MB
}

test('an upload interrupted by a reload goes on and arrives byte for byte', async ({ browser }, testInfo) => {
  test.slow()
  const account = newAccount('resume', PASSWORD)
  const context = await browser.newContext({ acceptDownloads: true })
  await registerAccount(context, account)
  // Saved through a download, not the save picker, so it can be read back.
  await context.addInitScript(() => {
    delete (window as { showSaveFilePicker?: unknown }).showSaveFilePicker
  })
  const page = await openDrive(context)

  const name = `resume-${Date.now()}.bin`
  const path = testInfo.outputPath(name)
  await writeFile(path, 40 * MB)

  // Slow enough to reload in the middle.
  let slow = true
  await context.route('**/api/uploads/**', async (route) => {
    if (slow && route.request().method() === 'PATCH') await new Promise((resolve) => setTimeout(resolve, 1500))
    await route.continue()
  })
  await startUpload(page, path)
  await expect.poll(() => percent(page, name), { timeout: 120_000 }).toBeGreaterThanOrEqual(30)
  await page.reload()

  slow = false
  const patches: string[] = []
  page.on('request', (r) => {
    if (r.method() === 'PATCH' && /\/api\/uploads\//.test(r.url())) patches.push(r.url())
  })
  await resumeFromPanel(page, name, path)
  await expect(item(page, name)).toBeVisible({ timeout: 120_000 })
  // It went on: fewer requests than a whole new upload (8 for 40 MB).
  expect(patches.length).toBeLessThan(8)
  await expect(page.getByRole('region', { name: 'Interrupted uploads' })).toHaveCount(0)

  const [download] = await Promise.all([page.waitForEvent('download'), itemAction(page, name, 'Download')])
  const saved = testInfo.outputPath(`downloaded-${name}`)
  await download.saveAs(saved)
  expect((await stat(saved)).size).toBe(40 * MB)
  expect(await sha256(saved)).toBe(await sha256(path))
  expect((await readFile(saved)).subarray(0, 4)).toEqual((await readFile(path)).subarray(0, 4))

  await context.close()
})

test('a multi-GB upload rides out a long loss of the connection and a reload', async ({ browser }, testInfo) => {
  const megabytes = Number(process.env.E2E_LARGE_UPLOAD_MB ?? 2048)
  test.setTimeout(Math.max(10 * 60_000, megabytes * 1_000))
  const account = newAccount('bigupload', PASSWORD)
  const context = await browser.newContext()
  await registerAccount(context, account)
  // The default 10 GB quota holds it; a bigger run needs the quota raised.
  const page = await openDrive(context)

  const name = `big-${megabytes}mb-${Date.now()}.bin`
  const path = testInfo.outputPath(name)
  await writeFile(path, megabytes * MB)

  const heaps: number[] = []
  await startUpload(page, path)
  await expect.poll(() => percent(page, name), { timeout: 600_000, intervals: [2_000] }).toBeGreaterThanOrEqual(20)
  heaps.push(await heapMb(page))

  // Offline for longer than the old retries lasted: it waits, then goes on.
  await context.setOffline(true)
  await expect(page.getByText('Waiting for the connection', { exact: false }).first()).toBeVisible({ timeout: 60_000 })
  const before = await percent(page, name)
  await page.waitForTimeout(30_000)
  await context.setOffline(false)
  await expect.poll(() => percent(page, name), { timeout: 180_000, intervals: [2_000] }).toBeGreaterThan(before)
  heaps.push(await heapMb(page))

  await expect.poll(() => percent(page, name), { timeout: 600_000, intervals: [2_000] }).toBeGreaterThanOrEqual(55)
  heaps.push(await heapMb(page))
  await page.reload()
  await resumeFromPanel(page, name, path)
  await expect.poll(() => percent(page, name), { timeout: 600_000, intervals: [2_000] }).toBeGreaterThanOrEqual(80)
  heaps.push(await heapMb(page))
  await expect(item(page, name)).toBeVisible({ timeout: 600_000 })

  // Two encrypted chunks in hand at most, whatever the size: the heap stays
  // far below the file.
  testInfo.annotations.push({ type: 'heap MB', description: heaps.map((h) => h.toFixed(0)).join(', ') })
  for (const heap of heaps) expect(heap).toBeLessThan(300)

  await context.close()
})
