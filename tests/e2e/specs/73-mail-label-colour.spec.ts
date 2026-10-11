import { expect, test, type BrowserContext, type Page } from '@playwright/test'
import { appUrl, newAccount, registerAccount } from '../fixtures/apps'

// A label (or folder) in any colour, not only the palette's: picked with the
// system colour picker or typed as a code. A code that is not one yet keeps
// Save off rather than saving the previous colour.

const PASSWORD = 'Deneme123*MailLabelColourPassword'
const SHOTS = process.env.MAIL_UX_SHOTS

async function openMail(context: BrowserContext): Promise<Page> {
  const page = await context.newPage()
  await page.goto(appUrl('mail'))
  await expect(page.getByRole('heading', { name: 'Inbox' })).toBeVisible({ timeout: 120_000 })
  return page
}

test('a label takes a colour of its own', async ({ browser }) => {
  const alice = newAccount('lblcolour', PASSWORD)
  const context = await browser.newContext({ viewport: { width: 1400, height: 900 } })
  await registerAccount(context, alice)
  const mail = await openMail(context)
  const nav = mail.getByRole('navigation')
  const icon = () => nav.getByRole('link', { name: 'Finans' }).locator('svg').first()

  // Typed: half a code keeps Save off; a whole one is used.
  await nav.getByRole('button', { name: 'New label' }).click()
  let dialog = mail.getByRole('dialog', { name: 'New label' })
  await dialog.getByLabel('Label name').fill('Finans')
  const code = dialog.getByLabel('Colour code')
  await code.fill('#1a2')
  await expect(dialog.getByText('Use a colour code like #4d85e0.')).toBeVisible()
  await expect(dialog.getByRole('button', { name: 'Save' })).toBeDisabled()
  await code.fill('1A2B3C')
  await expect(dialog.getByRole('button', { name: 'Save' })).toBeEnabled()
  // Not a palette colour: the custom swatch is the chosen one.
  await expect(dialog.getByRole('button', { pressed: true })).toHaveCount(0)
  await dialog.getByRole('button', { name: 'Save' }).click()
  await expect(icon()).toHaveCSS('color', 'rgb(26, 43, 60)', { timeout: 30_000 })

  // Picked: the colour picker's choice shows as its code and is saved.
  await nav.getByRole('link', { name: 'Finans' }).hover()
  await nav.getByRole('button', { name: 'Options for Finans' }).click()
  await mail.getByRole('menuitem', { name: 'Edit label' }).click()
  dialog = mail.getByRole('dialog', { name: 'Edit label' })
  await expect(dialog.getByLabel('Colour code')).toHaveValue('#1a2b3c')
  await dialog.getByLabel('Custom colour').fill('#ff8800')
  await expect(dialog.getByLabel('Colour code')).toHaveValue('#ff8800')
  if (SHOTS) await dialog.screenshot({ path: `${SHOTS}/label-colour.png` })
  await dialog.getByRole('button', { name: 'Save' }).click()
  await expect(icon()).toHaveCSS('color', 'rgb(255, 136, 0)', { timeout: 30_000 })

  // A palette swatch still works, and its code follows.
  await nav.getByRole('link', { name: 'Finans' }).hover()
  await nav.getByRole('button', { name: 'Options for Finans' }).click()
  await mail.getByRole('menuitem', { name: 'Edit label' }).click()
  dialog = mail.getByRole('dialog', { name: 'Edit label' })
  await dialog.getByRole('button', { name: '#54b77b' }).click()
  await expect(dialog.getByLabel('Colour code')).toHaveValue('#54b77b')
  await dialog.getByRole('button', { name: 'Save' }).click()
  await expect(icon()).toHaveCSS('color', 'rgb(84, 183, 123)', { timeout: 30_000 })

  await context.close()
})
