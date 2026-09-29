// A 12 MB file uploaded through tus, downloaded through the streaming
// decryptor, and compared byte for byte. The File System Access picker is
// removed so the download takes the browser's download path.

import { createHash } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { expect, test } from '@playwright/test'
import { newAccount, openDrive, registerAccount } from '../fixtures/apps'
import { item, itemAction } from '../fixtures/drive'

const PASSWORD = 'Deneme123*StreamDownloadPassword'
const FILE_BYTES = 12 * 1024 * 1024

test('a 12 MB upload downloads back byte for byte', async ({ browser }) => {
  test.slow()
  const context = await browser.newContext()
  await context.addInitScript(() => {
    delete (window as unknown as { showSaveFilePicker?: unknown }).showSaveFilePicker
  })
  await registerAccount(context, newAccount('download', PASSWORD))
  const page = await openDrive(context)

  const name = `roundtrip-12mb-${Date.now()}.bin`
  const original = Buffer.alloc(FILE_BYTES)
  for (let i = 0; i < FILE_BYTES; i++) original[i] = (i * 31 + 7) & 0xff
  let chunks = 0
  page.on('response', (response) => {
    if (response.request().method() === 'PATCH' && /^\/api\/uploads\/[^/]+$/.test(new URL(response.url()).pathname) && response.ok()) chunks += 1
  })
  await page.getByRole('button', { name: 'New' }).first().click()
  const [chooser] = await Promise.all([page.waitForEvent('filechooser'), page.getByRole('menuitem', { name: 'Upload files' }).click()])
  await chooser.setFiles({ name, mimeType: 'application/octet-stream', buffer: original })
  // Three 5 MB chunks, the last one finalising the file.
  await expect.poll(() => chunks, { timeout: 90_000 }).toBeGreaterThanOrEqual(3)
  // The listing from the server, not the upload's optimistic row.
  await page.reload()
  await expect(item(page, name)).toBeVisible({ timeout: 60_000 })

  const download = page.waitForEvent('download', { timeout: 90_000 })
  await itemAction(page, name, 'Download')
  const saved = await (await download).path()
  const bytes = await readFile(saved)
  expect(bytes.length).toBe(FILE_BYTES)
  expect(createHash('sha256').update(bytes).digest('hex')).toBe(createHash('sha256').update(original).digest('hex'))
  await context.close()
})
