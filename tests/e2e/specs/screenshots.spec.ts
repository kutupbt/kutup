// README screenshots, not a regression test: it overwrites docs/screenshots/
// with the current UI, so it runs only when asked:
//
//   KUTUP_README_SCREENSHOTS=1 npm exec -- playwright test specs/screenshots.spec.ts
//
// One test reuses one account and one set of sample content. Shots are
// 1280×720 viewport captures in the light theme, so they stack evenly in
// README.md.

import { mkdirSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { expect, test, type Page } from '@playwright/test'
import { appUrl, newAccount, openDrive, registerAccount } from '../fixtures/apps'
import { backFromEditor, createFolder, createNote, noteLive, renameItem } from '../fixtures/drive'
import { createOffice, officeReady, write } from '../fixtures/office'
import { addRectangle, createWhiteboard } from '../fixtures/whiteboard'

const SHOTS = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', 'docs', 'screenshots')

const NOTE = `# Field notes

Everything here is encrypted in this browser before it reaches the server.

## This week

- [x] Share the survey folder with the team
- [ ] Review the budget sheet
- [ ] Sketch the new floor plan

\`\`\`ts
const key = await deriveFolderKey(masterKey, folderId)
\`\`\`
`

async function shoot(page: Page, name: string) {
  await page.waitForTimeout(800)
  await page.screenshot({ path: join(SHOTS, name) })
}

test('README screenshots', async ({ browser }) => {
  test.skip(process.env.KUTUP_README_SCREENSHOTS !== '1', 'set KUTUP_README_SCREENSHOTS=1 to refresh docs/screenshots')
  test.setTimeout(600_000)
  mkdirSync(SHOTS, { recursive: true })
  const context = await browser.newContext({ viewport: { width: 1280, height: 720 }, colorScheme: 'light' })
  await context.addInitScript(() => localStorage.setItem('kutup-theme', 'light'))
  await registerAccount(context, newAccount('readme', 'Deneme123*ReadmeScreenshots'))
  const drive = await openDrive(context)

  // Sample content: folders, a note, a sheet, a whiteboard.
  for (const folder of ['Projects', 'Photos', 'Survey 2026']) await createFolder(drive, folder)

  const note = await createNote(drive)
  await noteLive(drive)
  await drive.locator('.cm-content').click()
  await drive.keyboard.press('Control+A')
  await drive.keyboard.insertText(NOTE)
  await drive.keyboard.press('Control+Home')
  await drive.getByRole('button', { name: 'Save', exact: true }).click()
  await shoot(drive, '02-notes-editor.png')
  await drive.getByRole('button', { name: 'History', exact: true }).click()
  await expect(drive.getByRole('heading', { name: 'Version history' })).toBeVisible()
  await shoot(drive, '05-version-history.png')
  await backFromEditor(drive)
  await renameItem(drive, note, 'Field notes.md')

  const logs: string[] = []
  drive.on('console', (message) => {
    if (message.text().includes('[kutup-bridge]')) logs.push(message.text())
  })
  await createOffice(drive, 'Spreadsheet')
  const sheet = { page: drive, logs }
  await officeReady(sheet)
  for (const [row, values] of [
    [0, ['Item', 'Q1', 'Q2']],
    [1, ['Hosting', '120', '140']],
    [2, ['Storage', '80', '95']],
  ] as const) {
    await write(sheet, 'Spreadsheet', values.join('\t'), { x: 98, y: 199 + row * 19 })
    await drive.keyboard.press('Enter')
  }
  await shoot(drive, '03-xlsx.png')
  await backFromEditor(drive)
  await renameItem(drive, 'Untitled spreadsheet.xlsx', 'Budget.xlsx')

  await createWhiteboard(drive)
  for (let i = 0; i < 3; i++) await addRectangle(drive)
  await shoot(drive, '04-whiteboard.png')
  await backFromEditor(drive)
  await renameItem(drive, 'Untitled whiteboard.excalidraw', 'Floor plan.excalidraw')

  await shoot(drive, '01-drive.png')

  const account = await context.newPage()
  await account.goto(appUrl('account', '/settings/security'))
  await expect(account.getByRole('main').getByRole('heading').first()).toBeVisible({ timeout: 60_000 })
  await shoot(account, '06-settings.png')
  await context.close()
})
