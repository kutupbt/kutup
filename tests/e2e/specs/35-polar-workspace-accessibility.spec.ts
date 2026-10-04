import AxeBuilder from '@axe-core/playwright'
import { expect, test, type Page } from '@playwright/test'
import { appUrl, newAccount, registerAccount, type App } from '../fixtures/apps'

type ThemePreference = 'light' | 'dark' | 'system'

const PASSWORD = 'Deneme123*AccessibilityPassword'
const PHONE = { width: 390, height: 844 }
const DESKTOP = { width: 1440, height: 900 }

/** Theme and language are kept per app origin, as each app stores them. */
async function setPreferences(page: Page, preferences: { theme?: ThemePreference; language?: 'en' | 'tr' }) {
  await page.evaluate(({ theme, language }) => {
    if (theme) localStorage.setItem('kutup-theme', theme)
    if (language) localStorage.setItem('kutup-lang', language)
  }, preferences)
  await page.reload()
  await page.waitForLoadState('domcontentloaded')
}

async function expectOneMainWithoutPageOverflow(page: Page) {
  await expect(page.getByRole('main')).toHaveCount(1)
  await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true)
}

async function expectNoSeriousAxeViolations(page: Page, checkpoint: string) {
  const result = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa']).analyze()
  const diagnostics = result.violations
    .filter(({ impact }) => impact === 'serious' || impact === 'critical')
    .map(({ id, impact, nodes }) => ({ id, impact, nodeCount: nodes.length, targets: nodes.slice(0, 3).map((node) => node.target.join(' ')) }))
  expect(diagnostics, `${checkpoint} contains serious or critical accessibility violations`).toEqual([])
}

/** Each signed-in app, where it opens, and what shows once it is ready. */
const WORKSPACES: Array<{ app: App; path: string; ready: (page: Page) => ReturnType<Page['getByRole']> }> = [
  { app: 'account', path: '/', ready: (page) => page.getByRole('heading', { name: /^Welcome/ }) },
  { app: 'account', path: '/settings/security', ready: (page) => page.getByRole('main').getByRole('heading').first() },
  // "New" moves into the sidebar drawer on phones; the explorer toolbar stays.
  { app: 'drive', path: '/', ready: (page) => page.getByRole('group', { name: 'View' }) },
  { app: 'chat', path: '/', ready: (page) => page.getByRole('region', { name: 'Conversations' }) },
  { app: 'chat', path: '/settings/devices', ready: (page) => page.getByTestId('chat-device-status') },
  { app: 'photos', path: '/', ready: (page) => page.getByRole('main').getByRole('heading').first() },
  { app: 'maps', path: '/', ready: (page) => page.getByRole('heading', { name: 'Your maps', exact: true }) },
  { app: 'office', path: '/', ready: (page) => page.getByRole('heading', { name: 'Start something new', exact: true }) },
]

test.describe('Responsive and accessibility gate', () => {
  test('sign-in pages are accessible in both themes and languages at phone and desktop widths', async ({ browser }) => {
    const context = await browser.newContext()
    const page = await context.newPage()

    await page.setViewportSize(PHONE)
    await page.goto(appUrl('account', '/login'))
    await expect(page.getByRole('heading', { name: 'Sign in to Kutup' })).toBeVisible()
    await setPreferences(page, { theme: 'dark' })
    await expectOneMainWithoutPageOverflow(page)
    await expectNoSeriousAxeViolations(page, 'phone-login-dark')

    await page.setViewportSize({ width: 430, height: 932 })
    await setPreferences(page, { theme: 'light', language: 'tr' })
    await expect(page.getByRole('heading', { name: "Kutup'a giriş yapın" })).toBeVisible()
    await expectOneMainWithoutPageOverflow(page)
    await expectNoSeriousAxeViolations(page, 'phone-login-turkish-light')

    await page.setViewportSize({ width: 768, height: 1024 })
    await page.emulateMedia({ reducedMotion: 'reduce', forcedColors: 'active' })
    await setPreferences(page, { theme: 'system' })
    await expectOneMainWithoutPageOverflow(page)

    await page.setViewportSize(DESKTOP)
    await page.emulateMedia({ reducedMotion: 'no-preference', forcedColors: 'none' })
    await setPreferences(page, { theme: 'light', language: 'en' })
    await expectOneMainWithoutPageOverflow(page)
    await expectNoSeriousAxeViolations(page, 'desktop-login-light')

    for (const [path, heading, checkpoint] of [
      ['/register', 'Create your Kutup account', 'desktop-register-light'],
      ['/recover', 'Recover your account', 'desktop-recovery-light'],
    ] as const) {
      await page.goto(appUrl('account', path))
      await expect(page.getByRole('heading', { name: heading })).toBeVisible()
      await expectOneMainWithoutPageOverflow(page)
      await expectNoSeriousAxeViolations(page, checkpoint)
    }
    await context.close()
  })

  test('every signed-in app passes axe in both themes at phone and desktop widths', async ({ browser }) => {
    test.slow()
    const context = await browser.newContext()
    await registerAccount(context, newAccount('a11y', PASSWORD))
    const page = await context.newPage()
    for (const { app, path, ready } of WORKSPACES) {
      const where = `${app}${path === '/' ? '' : path.replaceAll('/', '-')}`
      await page.setViewportSize(DESKTOP)
      await page.goto(appUrl(app, path))
      await expect(ready(page)).toBeVisible({ timeout: 120_000 })
      await setPreferences(page, { theme: 'light' })
      await expect(ready(page)).toBeVisible({ timeout: 60_000 })
      await expectOneMainWithoutPageOverflow(page)
      await expectNoSeriousAxeViolations(page, `desktop-${where}-light`)

      // Narrowing the window keeps the page: no reload, same address.
      const url = page.url()
      await page.setViewportSize(PHONE)
      await expect(page).toHaveURL(url)
      await setPreferences(page, { theme: 'dark' })
      await expect(ready(page)).toBeVisible({ timeout: 60_000 })
      await expectOneMainWithoutPageOverflow(page)
      await expectNoSeriousAxeViolations(page, `phone-${where}-dark`)
    }
    await context.close()
  })
})
