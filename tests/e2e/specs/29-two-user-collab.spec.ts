// Two *distinct* users collaborating on a shared note.
//
// The rest of the suite covers multi-TAB collab (one account, N tabs). This
// spec covers the cross-user path that multi-tab can't: userA shares a
// collection with userB (the collection key is sealed to userB's public key),
// userB unseals it with their own private key, opens the same note, and the
// two edit live — exercising the share crypto + the collab WS relay across two
// independent identities.
//
// userB is created through the real /register flow (client-side key generation
// + 24-word recovery phrase), so this also smoke-tests registration end-to-end.
import { test, expect, type BrowserContext, type Page } from '@playwright/test'
import { signInOrBootstrap } from '../fixtures/auth'

const NEW_PW = 'Deneme123*MyTestPasswordIsLong'

/** Pull the 24 mnemonic words off whatever page currently shows them. */
async function captureMnemonic(page: Page): Promise<string> {
  const allText = await page.evaluate(() => document.body.innerText)
  const seen = new Map<number, string>()
  for (const m of allText.matchAll(/(?:^|\s)(\d{1,2})[.)]\s*([a-z]+)\b/gim)) {
    const n = Number(m[1])
    if (n >= 1 && n <= 24 && !seen.has(n)) seen.set(n, m[2])
  }
  const words = Array.from({ length: 24 }, (_, i) => seen.get(i + 1))
  if (words.some((w) => !w)) throw new Error(`failed to capture mnemonic; got: ${words.join(' ')}`)
  return words.join(' ')
}

/** Register a brand-new account through the UI; leaves the context logged out. */
async function registerUser(ctx: BrowserContext, email: string, username: string): Promise<void> {
  const page = await ctx.newPage()
  await page.goto('/register')
  await page.locator('input[type=email]').fill(email)
  await page.getByLabel(/username/i).fill(username)
  const pw = page.locator('input[type=password]')
  await pw.nth(0).fill(NEW_PW)
  await pw.nth(1).fill(NEW_PW)
  await page.locator('button[type=submit]').click()

  // Argon2id key generation runs in a worker (a few seconds), then the
  // mnemonic step renders.
  await expect(page.getByText(/once/i).first()).toBeVisible({ timeout: 30_000 })
  const mnemonic = await captureMnemonic(page)

  // "I saved it" → confirm step → re-enter the phrase → submit.
  await page.getByRole('button', { name: /saved/i }).click()
  await page.locator('textarea').fill(mnemonic)
  await page.locator('button[type=submit]').click()
  await expect(page.getByRole('button', { name: /sign ?in/i })).toBeVisible({ timeout: 30_000 })
  await page.close()
}

/** Log into an existing (already set-up) account; returns the page on /drive. */
async function loginAs(ctx: BrowserContext, email: string, password: string): Promise<Page> {
  const page = await ctx.newPage()
  await page.goto('/login')
  await page.locator('input[type=email]').fill(email)
  await page.locator('input[type=password]').fill(password)
  await page.locator('button[type=submit]').click()
  await page.waitForURL(/drive/, { timeout: 30_000 })
  await page.waitForTimeout(2_000)
  return page
}

async function readEditor(page: Page): Promise<string> {
  return page.evaluate(() => {
    const el = document.querySelector('.cm-content')
    return el ? (el as HTMLElement).innerText : ''
  })
}

async function typeInEditor(page: Page, text: string): Promise<void> {
  await page.locator('.cm-content').click()
  await page.keyboard.type(text)
}

test.describe('two-user collaboration', () => {
  test('userA shares a note with userB; edits sync both ways', async ({ browser }) => {
    test.slow() // registration KDF + share crypto + collab handshakes
    const ctxA = await browser.newContext({ ignoreHTTPSErrors: true })
    const ctxB = await browser.newContext({ ignoreHTTPSErrors: true })

    // --- userA: the bootstrap admin ---
    const driveA = await signInOrBootstrap(ctxA)
    await driveA.waitForURL(/drive/, { timeout: 30_000 })

    // --- userB: a fresh registered account ---
    const tag = Date.now()
    const emailB = `bob-${tag}@kutup.local`
    await registerUser(ctxB, emailB, `bob${tag % 1_000_000}`)

    // --- userA creates a folder + a note inside it, then shares the folder ---
    const folderName = `shared-${tag}`
    await driveA.locator('button:has-text("New")').first().click()
    await driveA.locator('[role=menuitem]').filter({ hasText: /folder/i }).first().click()
    await driveA.getByRole('textbox').first().fill(folderName)
    await driveA.locator('button:has-text("Create")').last().click()
    await expect(driveA.getByText(folderName, { exact: false })).toBeVisible({ timeout: 15_000 })

    // Open the folder, create a note inside it.
    await driveA.getByText(folderName, { exact: false }).first().dblclick()
    await driveA.waitForTimeout(1_500)
    const noteName = `note-${tag}.md`
    const noteTabAP = ctxA.waitForEvent('page', { timeout: 30_000 })
    await driveA.locator('button:has-text("New")').first().click()
    await driveA.locator('[role=menuitem]').filter({ hasText: /note/i }).first().click()
    await driveA.getByRole('textbox').first().fill(noteName)
    await driveA.locator('button:has-text("Create")').last().click()
    const noteA = await noteTabAP
    await noteA.waitForLoadState('domcontentloaded')
    await noteA.waitForTimeout(5_000) // seed + persist

    const seed = `SEED-${tag} `
    await typeInEditor(noteA, seed)
    await noteA.waitForTimeout(3_000)

    // Back to My Files root (we're currently *inside* the folder, where its own
    // card isn't visible) so we can right-click the folder card to Share it.
    await driveA.getByRole('button', { name: /my files/i }).first().click()
    await expect(driveA.getByText(folderName, { exact: false }).first()).toBeVisible({
      timeout: 15_000,
    })

    // Share the folder with userB (right-click the folder card → Share).
    await driveA.getByText(folderName, { exact: false }).first().click({ button: 'right' })
    await driveA.getByRole('menuitem', { name: /^share$/i }).first().click()
    await driveA
      .getByPlaceholder(/email|username|recipient/i)
      .or(driveA.locator('input[autocomplete=email]'))
      .first()
      .fill(emailB)
    await driveA.getByRole('button', { name: /^share$/i }).click()
    await driveA.waitForTimeout(2_000)

    // --- userB logs in, opens the shared folder + note ---
    const driveB = await loginAs(ctxB, emailB, NEW_PW)
    await driveB.getByRole('button', { name: /shared with me/i }).click()
    await expect(driveB.getByText(folderName, { exact: false })).toBeVisible({ timeout: 30_000 })
    await driveB.getByText(folderName, { exact: false }).first().dblclick()
    await driveB.waitForTimeout(1_500)
    const noteTabBP = ctxB.waitForEvent('page', { timeout: 30_000 })
    await driveB.getByText(noteName, { exact: false }).first().dblclick()
    const noteB = await noteTabBP
    await noteB.waitForLoadState('domcontentloaded')
    noteB.on('console', (m) => {
      const t = m.text()
      if (t.includes('[text-collab]') || t.includes('[kutup-bridge]')) console.log('[noteB]', t)
    })

    // The editor must mount for userB — proves they decrypted the shared note's
    // file key with the collection key they unsealed from the share.
    await expect(noteB.locator('.cm-content')).toBeVisible({ timeout: 30_000 })
    await noteB.waitForTimeout(3_000) // let the collab WS connect + initial sync land

    // userB sees userA's seed → the share + key unseal + live sync worked.
    await expect.poll(() => readEditor(noteB), { timeout: 30_000 }).toContain(`SEED-${tag}`)

    // A → B: userA types, userB sees it.
    const aTag = `FROM-A-${tag} `
    await typeInEditor(noteA, aTag)
    await expect.poll(() => readEditor(noteB), { timeout: 30_000 }).toContain(`FROM-A-${tag}`)

    // B → A: userB types, userA sees it.
    const bTag = `FROM-B-${tag} `
    await typeInEditor(noteB, bTag)
    await expect.poll(() => readEditor(noteA), { timeout: 30_000 }).toContain(`FROM-B-${tag}`)

    await ctxA.close()
    await ctxB.close()
  })
})
