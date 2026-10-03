import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { expect, test } from '@playwright/test'
import { newAccount, openDrive, registerAccount } from '../fixtures/apps'
import { item, openItem } from '../fixtures/drive'

const PASSWORD = 'Deneme123*FolderUploadPassword'

test('uploading a folder recreates its tree in Drive', async ({ browser }) => {
  test.slow()
  const stamp = Date.now()
  const root = `pw-folder-${stamp}`
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'kutup-folder-upload-'))
  const files = [
    { rel: `${root}/a.txt`, content: 'alpha' },
    { rel: `${root}/2024/b.txt`, content: 'bravo' },
    { rel: `${root}/2024/c.txt`, content: 'charlie' },
  ]
  for (const file of files) {
    const abs = path.join(scratch, file.rel)
    fs.mkdirSync(path.dirname(abs), { recursive: true })
    fs.writeFileSync(abs, file.content)
  }

  try {
    const context = await browser.newContext()
    await registerAccount(context, newAccount('folderup', PASSWORD))
    const page = await openDrive(context)
    const folders: string[] = []
    const uploads: string[] = []
    page.on('response', (response) => {
      if (response.request().method() !== 'POST' || !response.ok()) return
      const pathname = new URL(response.url()).pathname
      if (/^\/api\/collections\/?$/.test(pathname)) folders.push(pathname)
      if (/^\/api\/uploads\/?$/.test(pathname)) uploads.push(pathname)
    })

    await page.getByRole('button', { name: 'New' }).first().click()
    const [chooser] = await Promise.all([page.waitForEvent('filechooser'), page.getByRole('menuitem', { name: 'Upload folder' }).click()])
    await chooser.setFiles(path.join(scratch, root))
    // Two folders (the root and 2024), one encrypted upload per file.
    await expect.poll(() => folders.length, { timeout: 60_000 }).toBeGreaterThanOrEqual(2)
    await expect.poll(() => uploads.length, { timeout: 60_000 }).toBeGreaterThanOrEqual(3)

    await page.reload()
    await openItem(page, root)
    await expect(item(page, 'a.txt')).toBeVisible({ timeout: 60_000 })
    await openItem(page, '2024')
    await expect(item(page, 'b.txt')).toBeVisible({ timeout: 60_000 })
    await expect(item(page, 'c.txt')).toBeVisible()
    await context.close()
  } finally {
    fs.rmSync(scratch, { recursive: true, force: true })
  }
})
