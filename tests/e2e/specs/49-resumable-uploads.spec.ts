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
import { mkdir, readFile, stat } from 'node:fs/promises'
import { expect, test, type BrowserContext, type Page } from '@playwright/test'
import { appUrl, newAccount, openDrive, registerAccount } from '../fixtures/apps'
import { createFolder, item, itemAction, openItem } from '../fixtures/drive'

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

/** PATCHes slowed down so a test can act in the middle of an upload. */
async function slowUploads(context: BrowserContext) {
  const state = { slow: true }
  await context.route('**/api/uploads/**', async (route) => {
    if (state.slow && route.request().method() === 'PATCH') await new Promise((resolve) => setTimeout(resolve, 1500))
    await route.continue()
  })
  return state
}

/** Started by `start`, slowed, then cut short by a reload: offered in the panel. */
async function interruptedIn(page: Page, name: string, start: () => Promise<void>) {
  await start()
  await expect.poll(() => percent(page, name), { timeout: 120_000 }).toBeGreaterThanOrEqual(25)
  await page.reload()
  await expect(page.getByRole('region', { name: 'Interrupted uploads' }).getByText(name, { exact: true })).toBeVisible({ timeout: 60_000 })
}

test('Photos: an upload interrupted by a reload goes on', async ({ browser }, testInfo) => {
  test.slow()
  const account = newAccount('photoresume', PASSWORD)
  const context = await browser.newContext()
  await registerAccount(context, account)
  const page = await context.newPage()
  await page.goto(appUrl('photos'))
  const upload = page.getByRole('button', { name: 'Upload', exact: true }).first()
  await expect(upload).toBeVisible({ timeout: 120_000 })

  const name = `clip-${Date.now()}.webm`
  const path = testInfo.outputPath(name)
  await writeFile(path, 40 * MB)
  const slow = await slowUploads(context)
  await interruptedIn(page, name, async () => {
    const [chooser] = await Promise.all([page.waitForEvent('filechooser'), upload.click()])
    await chooser.setFiles(path)
  })
  slow.slow = false
  await resumeFromPanel(page, name, path)
  await expect(page.getByText('Uploads complete')).toBeVisible({ timeout: 120_000 })
  await expect(page.getByRole('region', { name: 'Interrupted uploads' })).toHaveCount(0)
  await context.close()
})

test('discarding an interrupted upload frees it on the server, and another file is refused', async ({ browser }, testInfo) => {
  test.slow()
  const account = newAccount('discard', PASSWORD)
  const context = await browser.newContext()
  await registerAccount(context, account)
  const page = await openDrive(context)
  const name = `discard-${Date.now()}.bin`
  const path = testInfo.outputPath(name)
  await writeFile(path, 40 * MB)
  const slow = await slowUploads(context)
  await interruptedIn(page, name, () => startUpload(page, path))
  slow.slow = false

  // Another file under the same name is not the one it started with.
  const other = testInfo.outputPath(`other/${name}`)
  await mkdir(testInfo.outputPath('other'), { recursive: true })
  await writeFile(other, 40 * MB + 1)
  await resumeFromPanel(page, name, other)
  await expect(page.getByText('That is not the same file', { exact: false })).toBeVisible({ timeout: 60_000 })
  const panel = page.getByRole('region', { name: 'Interrupted uploads' })
  await expect(panel.getByText(name, { exact: true })).toBeVisible({ timeout: 60_000 })

  // Let go: the server's part goes too, and it is not offered again.
  const deleted = page.waitForResponse((r) => r.request().method() === 'DELETE' && /\/api\/uploads\//.test(r.url()))
  await panel.getByRole('button', { name: `Discard ${name}` }).click()
  expect((await deleted).status()).toBe(204)
  await expect(panel).toHaveCount(0)
  await page.reload()
  await expect(page.getByRole('button', { name: 'New' }).first()).toBeVisible({ timeout: 120_000 })
  await page.waitForTimeout(3_000)
  await expect(page.getByRole('region', { name: 'Interrupted uploads' })).toHaveCount(0)
  await expect(item(page, name)).toHaveCount(0)
  await context.close()
})

test('an upload running in one tab is not offered in another until that tab is gone', async ({ browser }, testInfo) => {
  test.slow()
  const account = newAccount('twotabs', PASSWORD)
  const context = await browser.newContext()
  await registerAccount(context, account)
  const first = await openDrive(context)
  const name = `tabs-${Date.now()}.bin`
  const path = testInfo.outputPath(name)
  await writeFile(path, 40 * MB)
  await slowUploads(context)
  await startUpload(first, path)
  await expect.poll(() => percent(first, name), { timeout: 120_000 }).toBeGreaterThanOrEqual(15)

  const second = await openDrive(context)
  await second.waitForTimeout(3_000)
  await expect(second.getByRole('region', { name: 'Interrupted uploads' })).toHaveCount(0)

  await first.close()
  await second.reload()
  await expect(second.getByRole('region', { name: 'Interrupted uploads' }).getByText(name, { exact: true })).toBeVisible({ timeout: 60_000 })
  await context.close()
})

test('an upload into a folder that moved to a new key is offered only to discard', async ({ browser }, testInfo) => {
  test.slow()
  const alice = newAccount('rekeyalice', PASSWORD)
  const bob = newAccount('rekeybob', PASSWORD)
  const context = await browser.newContext()
  await registerAccount(context, alice)
  await registerAccount(await browser.newContext(), bob)
  const page = await openDrive(context)
  const folder = `rekey-${Date.now()}`
  await createFolder(page, folder)
  await openItem(page, folder)
  await expect(page.getByRole('navigation', { name: 'Breadcrumb' })).toContainText(folder, { timeout: 30_000 })

  const name = `rekey-${Date.now()}.bin`
  const path = testInfo.outputPath(name)
  await writeFile(path, 40 * MB)
  const slow = await slowUploads(context)
  await interruptedIn(page, name, () => startUpload(page, path))
  slow.slow = false

  // Shared, then the person removed: the folder moves to a new key.
  await page.getByRole('link', { name: 'My files', exact: true }).first().click()
  await itemAction(page, folder, 'Share')
  const dialog = page.getByRole('dialog')
  await dialog.getByLabel('Email or Kutup address').fill(bob.email)
  await dialog.getByRole('button', { name: 'Share', exact: true }).click()
  await expect(dialog).toBeHidden({ timeout: 30_000 })
  await itemAction(page, folder, 'Share')
  await page.getByRole('dialog').getByRole('button', { name: /^What .+ can do$/ }).click()
  await page.getByRole('menuitem', { name: /^Remove/ }).click()
  await page.getByRole('dialog').getByRole('button', { name: 'Remove', exact: true }).click()
  await expect(page.getByText('Access removed')).toBeVisible({ timeout: 60_000 })
  await page.keyboard.press('Escape')

  await page.reload()
  const panel = page.getByRole('region', { name: 'Interrupted uploads' })
  await expect(panel.getByText('An upload into a folder that moved to a new key')).toBeVisible({ timeout: 60_000 })
  await expect(panel.getByRole('button', { name: /^Resume/ })).toHaveCount(0)
  await expect(panel.getByRole('button', { name: /^Discard/ })).toBeVisible()
  await context.close()
})

test('a folder upload interrupted by a reload: the file under way goes on, the ones not started are not offered', async ({ browser }, testInfo) => {
  test.slow()
  const account = newAccount('folderresume', PASSWORD)
  const context = await browser.newContext()
  await registerAccount(context, account)
  const page = await openDrive(context)

  // Two files of three parts each; the folder goes up one file at a time.
  const folder = `dropped-${Date.now()}`
  const dir = testInfo.outputPath(folder)
  await mkdir(dir, { recursive: true })
  const names = ['one.bin', 'two.bin']
  for (const name of names) await writeFile(`${dir}/${name}`, 15 * MB)

  const slow = await slowUploads(context)
  const patches: string[] = []
  page.on('response', (r) => {
    if (r.request().method() === 'PATCH' && /\/api\/uploads\//.test(r.url()) && r.ok()) patches.push(r.url())
  })
  await page.getByRole('button', { name: 'New' }).first().click()
  const [chooser] = await Promise.all([page.waitForEvent('filechooser'), page.getByRole('menuitem', { name: 'Upload folder' }).click()])
  await chooser.setFiles(dir)
  // In the middle of the first file.
  await expect.poll(() => patches.length, { timeout: 120_000 }).toBeGreaterThanOrEqual(1)
  expect(new Set(patches).size).toBe(1)
  await page.reload()

  slow.slow = false
  const panel = page.getByRole('region', { name: 'Interrupted uploads' })
  await expect(panel.getByTestId('interrupted-upload')).toHaveCount(1, { timeout: 60_000 })
  await expect(panel.getByText(`In ${folder}`, { exact: false })).toBeVisible()
  const underWay = (await panel.getByTestId('interrupted-upload').first().innerText()).includes('one.bin') ? 'one.bin' : 'two.bin'
  const notStarted = names.find((name) => name !== underWay)!
  await resumeFromPanel(page, underWay, `${dir}/${underWay}`)
  await expect(page.getByText('Uploads complete')).toBeVisible({ timeout: 120_000 })

  await openItem(page, folder)
  await expect(item(page, underWay)).toBeVisible({ timeout: 60_000 })
  // Not started before the reload: nothing remembered it (docs/roadmap.md).
  await expect(item(page, notStarted)).toHaveCount(0)
  await expect(page.getByRole('region', { name: 'Interrupted uploads' })).toHaveCount(0)
  await context.close()
})
