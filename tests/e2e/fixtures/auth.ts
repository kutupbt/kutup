import type { BrowserContext, Page } from '@playwright/test'

export const ADMIN_EMAIL = 'admin@kutup.local'
export const BOOTSTRAP_PW = 'adminpass'
// Long enough to pass zxcvbn score >= 2 in first-login (the form rejects weak pws).
export const NEW_PW = 'Deneme123*MyTestPasswordIsLong'

/**
 * Sign in to a freshly-wiped stack. Drives the full bootstrap → first-login →
 * mnemonic → drive flow. Tries NEW_PW first (in case the stack was already
 * bootstrapped in this run); falls back to BOOTSTRAP_PW + first-login.
 *
 * Returns the authenticated page parked on /drive.
 */
export async function signInOrBootstrap(ctx: BrowserContext): Promise<Page> {
  const page = await ctx.newPage()
  page.on('pageerror', (e) => console.log('[pageerror]', e.message))

  await page.goto('/login')
  await page.locator('input[type=email]').fill(ADMIN_EMAIL)
  await page.locator('input[type=password]').fill(NEW_PW)
  const respPromise = page.waitForResponse(
    (r) => r.url().includes('/auth/login') && r.request().method() === 'POST',
    { timeout: 15_000 },
  )
  await page.locator('button[type=submit]').click()
  const resp = await respPromise
  if (resp.status() === 401) {
    await page.locator('input[type=password]').fill(BOOTSTRAP_PW)
    await page.locator('button[type=submit]').click()
  }

  await page.waitForURL(/first-login|drive/, { timeout: 30_000 })

  if (page.url().includes('first-login')) {
    await page.locator('input[type=password]').nth(0).fill(NEW_PW)
    await page.locator('input[type=password]').nth(1).fill(NEW_PW)
    await page.locator('button[type=submit]').click()
    // Wait for the mnemonic page to render.
    await page.waitForTimeout(3_000)

    // Words appear as "1.foo" "2.bar" ... in document.body.innerText.
    const allText = await page.evaluate(() => document.body.innerText)
    const seen = new Map<number, string>()
    for (const m of allText.matchAll(/^\s*(\d+)\.\s*([a-z]+)\s*$/gim)) {
      const n = Number(m[1])
      if (n >= 1 && n <= 24) seen.set(n, m[2])
    }
    const mnemonic = Array.from({ length: 24 }, (_, i) => seen.get(i + 1)).join(' ')
    if (mnemonic.split(' ').filter(Boolean).length !== 24) {
      throw new Error(`failed to capture mnemonic; got: "${mnemonic}"`)
    }

    await page.locator('button').filter({ hasText: /saved/i }).first().click()
    await page.waitForTimeout(500)
    await page.locator('textarea').fill(mnemonic)
    await page.locator('button[type=submit]').click()
    await page.waitForURL(/drive/, { timeout: 30_000 })
  }

  // Wait for "My Files" auto-create + collections to load.
  await page.waitForTimeout(3_000)
  return page
}

/** Captures bridge + office collab logs from a page into an array. */
export function attachCollabLogs(page: Page, label = ''): string[] {
  const out: string[] = []
  page.on('console', (m) => {
    const t = m.text()
    if (t.includes('[kutup-bridge]') || t.includes('[office]') || t.includes('[ProtectedRoute]') || t.includes('[FirstLogin]') || t.includes('[text-collab]')) {
      out.push(t)
      if (label) console.log(`[${label}]`, t)
    }
  })
  return out
}
