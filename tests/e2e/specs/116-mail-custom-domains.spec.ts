import { writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { expect, test, type Locator, type Page } from '@playwright/test'
import { appUrl, newAccount, registerAccount, signInAsAdmin } from '../fixtures/apps'

// Custom domains (docs/plans/mail-custom-domains.md §11), Proton's settings
// on the mail gate's stack (scripts/test-mail-domains-browser.sh): its
// CoreDNS serves the zones this spec writes (KUTUP_MAIL_DNS_DIR), and the
// shared DKIM key is already published and active.
// - Settings → Domain names: Add domain runs Proton's wizard; Verify fails
//   until the TXT record is there, then passes; the MX, SPF, DKIM and DMARC
//   tabs list what to publish, and once published every badge turns good;
// - Identity and addresses: an address on the domain, made default and
//   back, disabled, enabled and deleted; the composer offers it as From;
// - the catch-all, set and shown; deleting the domain;
// - Administration → Mail domains: approving a domain when administrators
//   approve each, an account's own limits, deactivating a domain (its name
//   blocked) and lifting the block.

const PASSWORD = 'Deneme123*MailDomainsPassword'

/** Writes `<origin>.zone` for the stack's CoreDNS (reread every second). */
function writeZone(origin: string, records: string[]) {
  const dir = process.env.KUTUP_MAIL_DNS_DIR!
  const serial = Math.floor(Date.now() / 1000)
  const zone = [
    `$ORIGIN ${origin}.`,
    '$TTL 1',
    `@ IN SOA ns.${origin}. admin.${origin}. ${serial} 1 1 1 1`,
    `@ IN NS ns.${origin}.`,
    'ns IN A 127.0.0.1',
    ...records,
  ].join('\n')
  writeFileSync(join(dir, `${origin}.zone`), `${zone}\n`)
}

/** A TXT value as zone-file strings of at most 255 bytes. */
function txt(value: string): string {
  const parts: string[] = []
  for (let i = 0; i < value.length; i += 255) parts.push(`"${value.slice(i, i + 255)}"`)
  return parts.join(' ')
}

/** A host name as a zone file takes it: absolute, with its trailing dot. */
function absolute(name: string): string {
  return name.endsWith('.') ? name : `${name}.`
}

/** The values a wizard step's table lists, from its copy cells. */
async function values(wizard: Locator): Promise<{ host: string; value: string; priority: string }[]> {
  const rows = wizard.getByTestId('dns-record')
  const out = []
  for (let i = 0; i < (await rows.count()); i++) {
    const cells = rows.nth(i).getByRole('cell')
    const host = (await cells.nth(1).textContent())!.trim()
    const value = (await cells.nth(2).locator('[title]').first().getAttribute('title'))!
    const priority = (await cells.count()) > 3 ? (await cells.nth(3).textContent())!.trim() : ''
    out.push({ host, value, priority })
  }
  return out
}

async function tab(wizard: Locator, name: string) {
  await wizard.getByRole('tab', { name }).click()
}

async function badge(page: Page, label: string | RegExp) {
  return page.getByTestId('domain-status').getByText(label, { exact: typeof label === 'string' })
}

test('custom domains: the wizard, addresses on the domain, catch-all, deleting it', async ({ browser }) => {
  test.slow()
  expect(process.env.KUTUP_MAIL_DNS_DIR, 'run through scripts/test-mail-domains-browser.sh').toBeTruthy()
  const tag = Date.now().toString(36)
  const name = `d${tag}.test`
  const alice = newAccount('domalice', PASSWORD)
  const context = await browser.newContext({ viewport: { width: 1400, height: 900 } })
  await registerAccount(context, alice)
  const mail = await context.newPage()
  // Mail first (its sign-in lands on the inbox), then its settings.
  await mail.goto(appUrl('mail'))
  await expect(mail.getByRole('heading', { name: 'Inbox' })).toBeVisible({ timeout: 120_000 })
  await mail.goto(appUrl('mail', '/settings/domains'))
  await expect(mail.getByRole('heading', { name: 'Domain names' })).toBeVisible({ timeout: 60_000 })
  await expect(mail.getByText('No custom domain yet')).toBeVisible()

  // Step 1: the name ("www." warns).
  await mail.getByTestId('domain-add').click()
  const wizard = mail.getByTestId('domain-wizard')
  await expect(wizard.getByRole('heading', { name: 'Add domain' })).toBeVisible()
  await expect(wizard.getByRole('tab', { name: 'Verify' })).toBeDisabled()
  await wizard.getByTestId('domain-name').fill(`www.${name}`)
  await expect(wizard.getByText("'www' subdomains are typically not used for email.", { exact: false })).toBeVisible()
  await wizard.getByTestId('domain-name').fill(name)
  await wizard.getByTestId('domain-wizard-next').click()

  // Step 2: the TXT to publish; Verify fails before it is there.
  await expect(wizard.getByText(`we need to verify that you are the owner of ${name}`, { exact: false })).toBeVisible({ timeout: 60_000 })
  await expect(wizard.getByRole('tab', { name: 'MX' })).toBeDisabled()
  const [verify] = await values(wizard)
  expect(verify.host).toBe('@')
  expect(verify.value).toMatch(/^kutup-verification=/)
  await wizard.getByTestId('domain-wizard-next').click()
  await expect(mail.getByText('Verification did not succeed, please try again in an hour.')).toBeVisible({ timeout: 60_000 })
  writeZone(name, [`@ IN TXT ${txt(verify.value)}`])
  await expect(async () => {
    await wizard.getByTestId('domain-wizard-next').click()
    await expect(mail.getByText('Domain verified')).toBeVisible({ timeout: 5_000 })
  }).toPass({ timeout: 60_000 })

  // Steps 3-7: addresses (a link), then each record set; the DMARC value is editable.
  await expect(wizard.getByRole('link', { name: 'Add address' })).toBeVisible()
  await tab(wizard, 'MX')
  const mx = await values(wizard)
  expect(mx.length).toBeGreaterThan(0)
  expect(mx[0].priority).toMatch(/^\d+$/)
  await tab(wizard, 'SPF')
  const [spf] = await values(wizard)
  expect(spf.value).toMatch(/^v=spf1 include:/)
  await tab(wizard, 'DKIM')
  const dkim = await values(wizard)
  expect(dkim.length).toBeGreaterThan(0)
  await tab(wizard, 'DMARC')
  const dmarcInput = wizard.getByRole('textbox', { name: 'Value / Data / Points to' })
  const dmarc = await dmarcInput.inputValue()
  expect(dmarc).toMatch(/^v=DMARC1;/)
  await dmarcInput.fill('v=DMARC1; p=reject')
  await expect(dmarcInput).toHaveValue('v=DMARC1; p=reject')
  await expect(wizard.getByTestId('domain-wizard-next')).toHaveText('Done')
  await wizard.getByTestId('domain-wizard-next').click()
  await expect(wizard).toHaveCount(0)

  // Published: refresh, and every record's badge turns good.
  writeZone(name, [
    `@ IN TXT ${txt(verify.value)}`,
    // Host names absolute (a trailing dot), or the zone would read them as its own.
    ...mx.map((record) => `@ IN MX ${record.priority} ${absolute(record.value)}`),
    `@ IN TXT ${txt(spf.value)}`,
    `_dmarc IN TXT ${txt(dmarc)}`,
    ...dkim.map((record) => `${record.host} IN CNAME ${absolute(record.value)}`),
  ])
  await expect(async () => {
    await mail.getByRole('button', { name: 'Refresh status' }).click()
    for (const label of ['Verified', 'MX', 'SPF', 'DKIM']) {
      await expect(await badge(mail, label)).toHaveAttribute('data-tone', 'ok', { timeout: 5_000 })
    }
    // DMARC checks "relaxed" (Proton's RELAXED: DKIM aligned relaxed), which
    // Proton's badge shows neutral, never as a fault.
    await expect(await badge(mail, 'DMARC')).not.toHaveAttribute('data-tone', 'danger', { timeout: 5_000 })
  }).toPass({ timeout: 120_000 })
  await expect(await badge(mail, '0 addresses')).toHaveAttribute('data-tone', 'danger')
  await expect(mail.getByTestId('domains-used')).toContainText('1 /')

  // Addresses on it, in Identity and addresses.
  await mail.goto(appUrl('mail', '/settings/identity'))
  await expect(mail.getByRole('heading', { name: 'Identity and addresses' })).toBeVisible({ timeout: 60_000 })
  const addAddress = async (local: string) => {
    await mail.getByRole('button', { name: 'Add address' }).click()
    const dialog = mail.getByRole('dialog', { name: 'Add address' })
    await dialog.getByLabel('Address').fill(local)
    await expect(dialog.getByText(`@${name}`)).toBeVisible()
    await dialog.getByRole('button', { name: 'Save address' }).click()
    await expect(mail.getByText('Address added').first()).toBeVisible({ timeout: 60_000 })
  }
  await addAddress('info')
  await addAddress('sales')
  const row = (address: string) => mail.getByTestId('address-row').filter({ hasText: address })
  const info = `info@${name}`
  const sales = `sales@${name}`
  await expect(row(info).getByText('Active', { exact: true })).toBeVisible({ timeout: 60_000 })
  await expect(row(sales).getByText('Active', { exact: true })).toBeVisible()
  const act = async (address: string, action: string) => {
    await row(address).getByRole('button', { name: `Actions for ${address}` }).click()
    await mail.getByRole('menuitem', { name: action }).click()
  }
  // Default and back.
  await act(sales, 'Set as default')
  await expect(row(sales).getByText('Default', { exact: true })).toBeVisible({ timeout: 60_000 })
  // The composer offers the domain's addresses, the default first.
  await mail.goto(appUrl('mail', '/inbox'))
  await mail.getByRole('button', { name: 'New message' }).first().click()
  const composer = mail.getByRole('dialog', { name: 'New message' })
  await expect(composer.getByRole('combobox', { name: 'From' })).toContainText(sales, { timeout: 60_000 })
  await composer.getByRole('combobox', { name: 'From' }).click()
  await expect(mail.getByRole('option', { name: new RegExp(info) })).toBeVisible()
  await mail.keyboard.press('Escape')
  await composer.getByRole('button', { name: /Close/ }).first().click()
  await mail.goto(appUrl('mail', '/settings/identity'))
  const own = `${alice.username}@`
  await act(own, 'Set as default')
  await expect(row(own).getByText('Default', { exact: true })).toBeVisible({ timeout: 60_000 })
  // Disabled, enabled, deleted (Proton's confirmations).
  await act(sales, 'Disable')
  await mail.getByRole('alertdialog').getByRole('button', { name: 'Disable address' }).click()
  await expect(row(sales).getByText('Disabled', { exact: true })).toBeVisible({ timeout: 60_000 })
  await act(sales, 'Enable')
  await expect(row(sales).getByText('Active', { exact: true })).toBeVisible({ timeout: 60_000 })
  await act(sales, 'Delete address')
  await mail.getByRole('alertdialog').getByRole('button', { name: 'Delete address' }).click()
  await expect(mail.getByText('Address deleted').first()).toBeVisible({ timeout: 60_000 })
  await expect(row(sales)).toHaveCount(0)

  // The catch-all: info@, shown on the domain.
  await mail.goto(appUrl('mail', '/settings/domains'))
  await expect(await badge(mail, '1 address')).toHaveAttribute('data-tone', 'ok', { timeout: 60_000 })
  await mail.getByRole('button', { name: `Actions for ${name}` }).click()
  await mail.getByRole('menuitem', { name: 'Set catch-all' }).click()
  const catchAll = mail.getByTestId('catch-all-dialog')
  await catchAll.getByRole('checkbox', { name: `Make ${info} the catch-all address` }).click()
  await expect(mail.getByText('Catch-all address updated')).toBeVisible({ timeout: 60_000 })
  await catchAll.getByRole('button', { name: 'Close' }).last().click()
  await expect(await badge(mail, 'CATCH-ALL')).toHaveAttribute('data-tone', 'ok', { timeout: 60_000 })

  // Review opens the wizard on the domain, every tab reachable.
  await mail.getByRole('button', { name: `Actions for ${name}` }).click()
  await mail.getByRole('menuitem', { name: 'Review' }).click()
  await expect(wizard.getByRole('heading', { name: 'Edit domain' })).toBeVisible()
  await expect(wizard.getByRole('tab', { name: 'DMARC' })).toBeEnabled()
  await wizard.getByRole('button', { name: 'Close' }).last().click()

  // Deleting it.
  await mail.getByRole('button', { name: `Actions for ${name}` }).click()
  await mail.getByRole('menuitem', { name: 'Delete' }).click()
  const confirm = mail.getByRole('alertdialog')
  await expect(confirm).toContainText(`if you delete this domain ${name}, all the addresses associated with it will be disabled`)
  await confirm.getByRole('button', { name: 'Delete' }).click()
  await expect(mail.getByText('Domain deleted')).toBeVisible({ timeout: 60_000 })
  await expect(mail.getByText('No custom domain yet')).toBeVisible()
  await mail.goto(appUrl('mail', '/settings/identity'))
  await expect(row(info)).toHaveCount(0, { timeout: 60_000 })

  await context.close()
})

/** Sets who may add domains on the administrators' page. */
async function setMode(admin: Page, label: 'Everyone may add domains' | 'Administrators approve each domain') {
  await admin.goto(appUrl('account', '/admin/mail/domains'))
  const mode = admin.getByRole('combobox', { name: 'Who may add domains' })
  await expect(mode).toBeVisible({ timeout: 60_000 })
  if ((await mode.textContent())?.includes(label)) return
  await mode.click()
  await admin.getByRole('option', { name: label }).click()
  await admin.getByRole('button', { name: 'Save' }).click()
  await expect(admin.getByText('Settings saved').first()).toBeVisible({ timeout: 30_000 })
}

test('custom domains: the administrators’ page', async ({ browser }) => {
  test.slow()
  expect(process.env.KUTUP_MAIL_DNS_DIR, 'run through scripts/test-mail-domains-browser.sh').toBeTruthy()
  const name = `a${Date.now().toString(36)}.test`
  const adminContext = await browser.newContext({ viewport: { width: 1400, height: 900 } })
  await signInAsAdmin(adminContext)
  const admin = await adminContext.newPage()
  await setMode(admin, 'Administrators approve each domain')
  try {
    // Bob adds and verifies a domain; it waits for an administrator.
    const bob = newAccount('domadmin', PASSWORD)
    const context = await browser.newContext({ viewport: { width: 1400, height: 900 } })
    await registerAccount(context, bob)
    const mail = await context.newPage()
    await mail.goto(appUrl('mail'))
    await expect(mail.getByRole('heading', { name: 'Inbox' })).toBeVisible({ timeout: 120_000 })
    await mail.goto(appUrl('mail', '/settings/domains'))
    await mail.getByTestId('domain-add').click()
    const wizard = mail.getByTestId('domain-wizard')
    await wizard.getByTestId('domain-name').fill(name)
    await wizard.getByTestId('domain-wizard-next').click()
    await expect(wizard.getByText(`we need to verify that you are the owner of ${name}`, { exact: false })).toBeVisible({ timeout: 60_000 })
    const [verify] = await values(wizard)
    writeZone(name, [`@ IN TXT ${txt(verify.value)}`])
    await expect(async () => {
      await wizard.getByTestId('domain-wizard-next').click()
      await expect(mail.getByText('Domain verified')).toBeVisible({ timeout: 5_000 })
    }).toPass({ timeout: 60_000 })
    await wizard.getByRole('button', { name: 'Close' }).first().click()

    // Approved by an administrator.
    await admin.reload()
    const row = admin.getByTestId('admin-domain-row').filter({ hasText: name })
    await expect(row.getByText('Awaiting approval')).toBeVisible({ timeout: 60_000 })
    await row.getByRole('button', { name: 'Approve' }).click()
    await expect(admin.getByText('Domain approved').first()).toBeVisible({ timeout: 30_000 })
    await expect(row.getByText('Awaiting approval')).toHaveCount(0)

    // Bob's own limit: three domains, shown on his page.
    await admin.goto(appUrl('account', '/admin/users'))
    await admin.getByRole('link', { name: new RegExp(bob.username) }).first().click()
    const limits = admin.getByTestId('mail-domain-overrides')
    await expect(limits.getByText('From 0 to 100.')).toBeVisible({ timeout: 60_000 })
    await limits.getByRole('spinbutton', { name: 'Domains' }).fill('3')
    await limits.getByRole('button', { name: 'Save' }).click()
    await expect(admin.getByText('Limits saved').first()).toBeVisible({ timeout: 30_000 })
    await mail.reload()
    await expect(mail.getByTestId('domains-used')).toHaveText('1 / 3 domains used', { timeout: 60_000 })

    // Deactivated: the name blocked, then the block lifted.
    await admin.goto(appUrl('account', '/admin/mail/domains'))
    await admin.getByTestId('admin-domain-row').filter({ hasText: name }).getByRole('button', { name: 'Deactivate' }).click()
    const dialog = admin.getByRole('alertdialog').or(admin.getByRole('dialog')).filter({ hasText: `Deactivate ${name}?` })
    await dialog.getByLabel(`Type ${name} to confirm`).fill(name)
    await dialog.getByRole('button', { name: 'Deactivate' }).click()
    await expect(admin.getByText('Domain deactivated').first()).toBeVisible({ timeout: 30_000 })
    const block = admin.getByTestId('admin-domain-block').filter({ hasText: name })
    await expect(block).toBeVisible({ timeout: 30_000 })
    await block.getByRole('button', { name: 'Lift the block' }).click()
    await expect(admin.getByText('Block lifted').first()).toBeVisible({ timeout: 30_000 })
    await expect(block).toHaveCount(0)
    await context.close()
  } finally {
    await setMode(admin, 'Everyone may add domains')
    await adminContext.close()
  }
})
