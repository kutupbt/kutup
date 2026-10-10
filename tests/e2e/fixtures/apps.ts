import { expect, type BrowserContext, type Locator, type Page } from '@playwright/test'

/**
 * Kutup serves one web app per hostname: account, drive, chat, photos, maps
 * and office, plus the editor sandbox. A server's apps are described by an origin
 * template in which `{app}` stands for the app's name, for example
 * `https://{app}.localhost:38443` for the single-server stack or
 * `http://{app}.a.test:39081` for the first federation server.
 */
export type App = 'account' | 'drive' | 'chat' | 'photos' | 'maps' | 'office' | 'contacts' | 'mail' | 'editor'
export type Server = 'primary' | 'secondary'

export const APPS: readonly App[] = ['account', 'drive', 'chat', 'photos', 'maps', 'office', 'contacts', 'mail', 'editor']

export const PRIMARY_ORIGIN_TEMPLATE = process.env.E2E_APP_ORIGIN ?? 'https://{app}.localhost:38443'
export const SECONDARY_ORIGIN_TEMPLATE = process.env.E2E_SECONDARY_APP_ORIGIN

function template(server: Server): string {
  if (server === 'primary') return PRIMARY_ORIGIN_TEMPLATE
  if (!SECONDARY_ORIGIN_TEMPLATE) throw new Error('E2E_SECONDARY_APP_ORIGIN is required for two-server specs')
  return SECONDARY_ORIGIN_TEMPLATE
}

export function hasSecondaryServer(): boolean {
  return Boolean(SECONDARY_ORIGIN_TEMPLATE)
}

export function appOrigin(app: App, server: Server = 'primary'): string {
  return template(server).replace('{app}', app).replace(/\/+$/, '')
}

export function appUrl(app: App, path = '/', server: Server = 'primary'): string {
  return `${appOrigin(app, server)}${path.startsWith('/') ? path : `/${path}`}`
}

/**
 * Where this test process (not the browser) reaches a server's API. Node
 * cannot resolve test hostnames such as `*.a.test`, so two-server runs name
 * the edge directly (E2E_API_URL, E2E_SECONDARY_API_URL).
 */
export function apiUrl(path: string, server: Server = 'primary'): string {
  const base = (server === 'primary' ? process.env.E2E_API_URL : process.env.E2E_SECONDARY_API_URL) ?? appOrigin('account', server)
  return `${base.replace(/\/+$/, '')}/api${path.startsWith('/') ? path : `/${path}`}`
}

/** The federation domain of a server, when E2E_*_DOMAIN names it. */
export function serverDomain(server: Server = 'primary'): string {
  const value = server === 'primary' ? process.env.E2E_DOMAIN : process.env.E2E_SECONDARY_DOMAIN
  if (!value) throw new Error(`E2E_${server === 'primary' ? '' : 'SECONDARY_'}DOMAIN is required`)
  return value
}

/** Every origin of both servers, for browser flags. */
export function allOrigins(): string[] {
  const servers: Server[] = hasSecondaryServer() ? ['primary', 'secondary'] : ['primary']
  return servers.flatMap((server) => APPS.map((app) => appOrigin(app, server)))
}

export interface Account {
  email: string
  username: string
  password: string
  server: Server
}

/** A fresh account's details; nothing is created yet. */
export function newAccount(prefix: string, password: string, server: Server = 'primary'): Account {
  const run = `${Date.now().toString(36)}${process.pid.toString(36)}${Math.random().toString(36).slice(2, 6)}`
  const username = `${prefix}${run}`.toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 32)
  return { email: `${username}@kutup.dev`, username, password, server }
}

/**
 * Creates the account in the account app, the way a person does: details,
 * the recovery phrase shown once, and its confirmation. Leaves the context
 * signed in on the launcher and returns the phrase, which stays in this
 * process only.
 */
export async function registerAccount(context: BrowserContext, account: Account): Promise<string> {
  const page = await context.newPage()
  await page.goto(appUrl('account', '/register', account.server))
  await page.getByLabel('Email', { exact: true }).fill(account.email)
  await page.getByLabel('Username', { exact: true }).fill(account.username)
  const phrase = await finishNewKeys(page, account.password)
  await page.close()
  return phrase
}

/**
 * The key wizard shared by registration and an admin-created account's
 * first sign-in: a new password, the recovery phrase shown once, and its
 * confirmation. Ends on the launcher with the session saved; returns the
 * phrase, which stays in this process only.
 */
export async function finishNewKeys(page: Page, password: string): Promise<string> {
  await page.getByLabel('New password', { exact: true }).fill(password)
  await page.getByLabel('Repeat password', { exact: true }).fill(password)
  await submitThroughRateLimit(page, 'Continue', page.getByRole('heading', { name: 'Your recovery phrase' }))
  const words = (await page.locator('ol li span:last-child').allTextContents()).map((word) => word.trim())
  if (words.length !== 24 || words.some((word) => !/^[a-z]+$/.test(word))) {
    throw new Error(`failed to capture the recovery phrase (${words.length} words)`)
  }
  await page.getByRole('button', { name: 'I have saved my recovery phrase' }).click()
  for (const label of await page.locator('label').allTextContents()) {
    const n = Number(label.match(/Word (\d+)/)?.[1])
    if (n) await page.getByLabel(`Word ${n}`, { exact: true }).fill(words[n - 1])
  }
  await submitThroughRateLimit(page, 'Confirm and continue', page.getByRole('heading', { name: /Welcome/ }))
  await sessionSaved(page)
  return words.join(' ')
}

/**
 * The isolated test stack's break-glass administrator
 * (tests/e2e/docker-compose.isolated.yml). Its first sign-in uses the
 * bootstrap password and sets ADMIN_PASSWORD through the key wizard.
 */
export const ADMIN_EMAIL = process.env.E2E_ADMIN_EMAIL ?? 'admin@kutup.dev'
const ADMIN_BOOTSTRAP_PASSWORD = process.env.E2E_BOOTSTRAP_PASSWORD ?? 'Bootstrap*Temporary123'
const ADMIN_PASSWORD = process.env.E2E_ADMIN_PASSWORD ?? 'Deneme123*AdminLongPassword'

/** Signs the context in as the administrator, finishing its setup once. */
export async function signInAsAdmin(context: BrowserContext): Promise<void> {
  const page = await context.newPage()
  for (const password of [ADMIN_PASSWORD, ADMIN_BOOTSTRAP_PASSWORD]) {
    await page.goto(appUrl('account', '/login'))
    await page.getByLabel('Email', { exact: true }).fill(ADMIN_EMAIL)
    await page.getByLabel('Password', { exact: true }).fill(password)
    const welcome = page.getByRole('heading', { name: /Welcome/ })
    const setup = page.getByRole('heading', { name: 'Finish setting up your account' })
    const failed = page.getByRole('alert').filter({ hasText: 'Sign-in failed' })
    await submitThroughRateLimit(page, 'Sign in', welcome.or(setup).or(failed).first())
    if (await welcome.isVisible()) break
    if (await setup.isVisible()) {
      await finishNewKeys(page, ADMIN_PASSWORD)
      break
    }
    if (password === ADMIN_BOOTSTRAP_PASSWORD) throw new Error('the test administrator cannot sign in')
  }
  await sessionSaved(page)
  await page.close()
}

/** Signs in through the account app; the context's apps then fork from it. */
export async function signIn(context: BrowserContext, account: Account): Promise<void> {
  const page = await context.newPage()
  await page.goto(appUrl('account', '/login', account.server))
  await page.getByLabel('Email', { exact: true }).fill(account.email)
  await page.getByLabel('Password', { exact: true }).fill(account.password)
  // The launcher greets in the account's language, which may be Turkish.
  await submitThroughRateLimit(page, 'Sign in', page.getByRole('heading', { name: /Welcome|Hoş geldiniz/ }))
  await sessionSaved(page)
  await page.close()
}

/**
 * Presses a sign-in or registration button until `done` shows. The edge
 * limits these endpoints (nginx: 10 a minute, burst 5); a suite that creates
 * several accounts meets that limit the way a person would, with "Too many
 * attempts", and waits for it to refill before trying again.
 */
async function submitThroughRateLimit(page: Page, button: string, done: Locator): Promise<void> {
  const limited = page.getByRole('alert').filter({ hasText: 'Too many attempts' })
  for (let attempt = 1; ; attempt++) {
    const retrying = await limited.isVisible()
    await page.getByRole('button', { name: button, exact: true }).click()
    // The previous attempt's message stays until this one is under way.
    if (retrying) await expect(limited).toBeHidden({ timeout: 30_000 })
    await expect(done.or(limited).first()).toBeVisible({ timeout: 120_000 })
    if (await done.isVisible()) return
    if (attempt === 8) throw new Error(`${button}: still rate limited after ${attempt} attempts`)
    await page.waitForTimeout(8_000)
  }
}

/**
 * The launcher shows as soon as the session is active; the sealed copy that
 * lets other tabs and apps resume it is written just after. Wait for it
 * before closing the tab.
 */
async function sessionSaved(page: Page): Promise<void> {
  await page.waitForFunction(() => localStorage.getItem('kutup-session') !== null, undefined, { timeout: 30_000 })
}

/** Opens Drive on a signed-in context and waits for its listing. */
export async function openDrive(context: BrowserContext, server: Server = 'primary', path = '/'): Promise<Page> {
  const page = await context.newPage()
  await page.goto(appUrl('drive', path, server))
  await expect(page.getByRole('button', { name: 'New' }).first()).toBeVisible({ timeout: 120_000 })
  return page
}
