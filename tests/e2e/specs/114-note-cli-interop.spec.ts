// A note edited in a browser tab (Yjs in JavaScript) and through `kutup
// sync` (yrs in Rust) at once: the two peers' edits merge, each once
// (docs/plans/cli-yjs-sync.md). The CLI binary comes from KUTUP_CLI (built
// with `cargo build -p kutup-cli`); without it the spec is skipped.

import { execFileSync } from 'node:child_process'
import { mkdtempSync, readFileSync, writeFileSync, appendFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { expect, test } from '@playwright/test'
import { appOrigin, newAccount, openDrive, registerAccount } from '../fixtures/apps'
import { noteLive, noteText, openItem, typeAtEnd, waitForFilePage } from '../fixtures/drive'

const PASSWORD = 'Deneme123*NoteCliPassword'
const CLI = process.env.KUTUP_CLI

/** How many times `needle` is in `text`. */
const count = (text: string, needle: string) => text.split(needle).length - 1

test('a tab and the CLI edit one note, and every edit lands once', async ({ browser }) => {
  test.skip(!CLI, 'KUTUP_CLI (the kutup binary) is not set')
  test.slow()
  const account = newAccount('notecli', PASSWORD)
  const context = await browser.newContext()
  await registerAccount(context, account)

  const dir = mkdtempSync(join(tmpdir(), 'kutup-cli-interop-'))
  const profile = `interop-${process.pid}-${Date.now()}`
  const env = { ...process.env, KUTUP_PASSWORD: PASSWORD, KUTUP_INSECURE_TLS: '1' }
  const kutup = (...args: string[]) => execFileSync(CLI!, ['--profile', profile, ...args], { env, encoding: 'utf8' })
  try {
    kutup('login', '--server', appOrigin('drive'), '--username', account.username)
    const folderName = `Interop ${Date.now()}`
    const folder = JSON.parse(kutup('--json', 'mkdir', folderName)).id as string
    const local = join(dir, 'sync')
    const note = join(local, 'plan.md')
    execFileSync('mkdir', ['-p', local])
    // Uploaded by the CLI; nobody has opened it yet.
    writeFileSync(note, 'Plan from the CLI\nline two\n')
    kutup('sync', local, folder)

    // The tab opens it (its first content: the seed) and types.
    const drive = await openDrive(context)
    await openItem(drive, folderName)
    await openItem(drive, 'plan.md')
    await waitForFilePage(drive)
    await noteLive(drive)
    await expect.poll(() => noteText(drive)).toContain('Plan from the CLI')
    await typeAtEnd(drive, ' tab-edit-1')
    await drive.waitForTimeout(1_500)

    // The CLI pulls the tab's edit: the seed once, the edit once.
    kutup('sync', local, folder)
    let text = readFileSync(note, 'utf8')
    expect(count(text, 'Plan from the CLI')).toBe(1)
    expect(count(text, 'tab-edit-1')).toBe(1)

    // The CLI's edit reaches the open tab live.
    appendFileSync(note, 'cli-edit-1\n')
    kutup('sync', local, folder)
    await expect.poll(() => noteText(drive), { timeout: 30_000 }).toContain('cli-edit-1')

    // Both at once: the tab types while the CLI holds its own edit.
    await typeAtEnd(drive, ' tab-edit-2')
    appendFileSync(note, 'cli-edit-2\n')
    await drive.waitForTimeout(1_500)
    kutup('sync', local, folder)
    await expect.poll(() => noteText(drive), { timeout: 30_000 }).toContain('cli-edit-2')
    text = readFileSync(note, 'utf8')
    const shown = await noteText(drive)
    for (const edit of ['Plan from the CLI', 'tab-edit-1', 'tab-edit-2', 'cli-edit-1', 'cli-edit-2']) {
      expect(count(text, edit), `file: ${edit}`).toBe(1)
      expect(count(shown, edit), `tab: ${edit}`).toBe(1)
    }
    // Synced again with nothing new: nothing changes.
    kutup('sync', local, folder)
    expect(readFileSync(note, 'utf8')).toBe(text)
  } finally {
    try {
      kutup('logout')
    } catch {
      // Signed out already.
    }
    rmSync(dir, { recursive: true, force: true })
    await context.close()
  }
})
