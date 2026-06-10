// E2E coverage for the folder upload path.
//
// Drive's new "Folder" button hooks a hidden `<input webkitdirectory>`,
// fans the resulting flat FileList (each entry carries
// `webkitRelativePath`) into FolderEntry[], creates the matching
// subcollection tree top-down, then queues per-file streamUploads.
//
// `fileChooser.setFiles()` against a webkitdirectory input requires a
// real on-disk directory path — Playwright reads the tree itself. We
// stage `/tmp/pw-folder-<ts>/<root>/{a.bin, 2024/{b.bin, c.bin}}`
// before opening the picker.
//
// We assert on the WIRE-LEVEL invariants the feature must satisfy
// rather than on DOM observability: a folder upload of N files in M
// directories must produce M `POST /api/collections` responses
// (subcollection creates, including the root) plus at least 1
// `POST /api/uploads` (tus create) per file. CSS-truncates the
// rendered folder name to "pw-fold…", which makes DOM-text locators
// flaky; the network proof is unambiguous.

import { test, expect } from '@playwright/test'
import { signInOrBootstrap } from '../fixtures/auth'
import * as fs from 'node:fs'
import * as path from 'node:path'
import * as os from 'node:os'

const TS = Date.now()
const ROOT = 'pw-folder-' + TS
const SUB = '2024'
const SCRATCH = path.join(os.tmpdir(), `pw-folder-spec-${TS}`)
// Files keyed by their `webkitRelativePath` once the picker resolves
// them. The first segment is the picked-folder name.
const FILES: { rel: string; content: string }[] = [
  { rel: `${ROOT}/a.bin`,            content: 'plain text alpha' },
  { rel: `${ROOT}/${SUB}/b.bin`,     content: 'plain text bravo' },
  { rel: `${ROOT}/${SUB}/c.bin`,     content: 'plain text charlie' },
]

function stageDirectory(): string {
  fs.rmSync(SCRATCH, { recursive: true, force: true })
  for (const f of FILES) {
    const abs = path.join(SCRATCH, f.rel)
    fs.mkdirSync(path.dirname(abs), { recursive: true })
    fs.writeFileSync(abs, f.content)
  }
  return path.join(SCRATCH, ROOT)
}

test.describe('folder upload', () => {
  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext({ ignoreHTTPSErrors: true })
    await signInOrBootstrap(ctx)
    await ctx.close()
  })

  test.afterAll(() => {
    fs.rmSync(SCRATCH, { recursive: true, force: true })
  })

  test('uploads a folder tree, hitting create-collection + tus-upload endpoints', async ({ context }) => {
    const folderPath = stageDirectory()

    const page = await signInOrBootstrap(context)
    await page.waitForURL(/\/drive/, { timeout: 30_000 })
    // Drive is ready once the My Files listing renders: a Folders/Files section
    // heading (populated drive) or the empty-state dropzone. The old /folders/i-only
    // proxy hung forever on a folder-less account (drive loaded, but no Folders heading).
    await expect(
      page
        .getByRole('heading', { name: /folders|files/i })
        .or(page.getByText(/drop files here/i))
        .first(),
    ).toBeVisible({ timeout: 30_000 })

    // Count create-collection POSTs + create-upload POSTs the pipeline
    // makes after we trigger the picker. We expect:
    //   - 2 collection creates: ROOT + SUB
    //   - 3 tus create POSTs: one per FILE
    const collectionCreates: number[] = []
    const tusCreates: number[] = []
    page.on('response', (res) => {
      if (res.request().method() !== 'POST' || !res.ok()) return
      const url = res.url()
      if (/\/api\/collections\/?$/.test(url)) collectionCreates.push(1)
      if (/\/api\/uploads\/?$/.test(url)) tusCreates.push(1)
    })

    // Click the "Upload folder" toolbar button (testid'd to avoid
    // colliding with file-cards labelled "Folder").
    const [fileChooser] = await Promise.all([
      page.waitForEvent('filechooser'),
      page.getByTestId('upload-folder-button').click(),
    ])
    await fileChooser.setFiles(folderPath)

    // Poll for the expected wire-level outcome. uploadFolder creates
    // the subcollections sequentially, then streams the files; on a
    // local docker stack the full sequence completes in <10 s, but
    // give it 60 s of headroom for slow CI.
    await expect
      .poll(() => collectionCreates.length, {
        timeout: 60_000,
        message: 'waiting for both subcollection creates (root + 2024)',
      })
      .toBeGreaterThanOrEqual(2)
    await expect
      .poll(() => tusCreates.length, {
        timeout: 60_000,
        message: 'waiting for tus create POSTs (one per file × 3)',
      })
      .toBeGreaterThanOrEqual(3)
  })
})
