import { expect, test, type BrowserContext, type Page } from '@playwright/test'
import { apiUrl, appUrl, newAccount, registerAccount } from '../fixtures/apps'
import { openWhenArrived } from '../fixtures/mail'

// Body search in the browser (docs/plans/mail-body-search.md), as Proton's
// "Search message content": a word only in a message's text is not found by
// the server's search; once the reader turns it on, the browser indexes the
// mailbox (encrypted, in IndexedDB) and finds it; deleting the local search
// data takes it away.

const PASSWORD = 'Deneme123*MailBodySearchPassword'

async function openMail(context: BrowserContext): Promise<Page> {
  const page = await context.newPage()
  await page.goto(appUrl('mail'))
  await expect(page.getByRole('heading', { name: 'Inbox' })).toBeVisible({ timeout: 120_000 })
  return page
}

async function search(mail: Page, words: string) {
  const box = mail.getByRole('searchbox', { name: 'Search mail' })
  await box.fill(words)
  await box.press('Enter')
}

test('body search: off, then on and built, then deleted', async ({ browser, request }) => {
  test.slow()
  const settings = (await (await request.get(apiUrl('/auth/settings'))).json()) as { chat: { serverName: string } }
  const domain = settings.chat.serverName
  const alice = newAccount('bsalice', PASSWORD)
  const bob = newAccount('bsbob', PASSWORD)
  const aliceContext = await browser.newContext({ viewport: { width: 1400, height: 900 } })
  const bobContext = await browser.newContext({ viewport: { width: 1400, height: 900 } })
  await registerAccount(aliceContext, alice)
  await registerAccount(bobContext, bob)
  const mail = await openMail(aliceContext)
  const bobMail = await openMail(bobContext)
  const tag = Date.now().toString(36)
  const subject = `Toplantı ${tag}`
  // Only in the text, with Turkish letters the search folds.
  const word = `Gölcük${tag}`

  await bobMail.getByRole('button', { name: 'New message' }).first().click()
  const composer = bobMail.getByRole('dialog', { name: 'New message' })
  await composer.getByRole('combobox', { name: 'To' }).fill(`${alice.username}@${domain}`)
  await composer.getByRole('combobox', { name: 'To' }).press('Enter')
  await composer.getByRole('textbox', { name: 'Subject' }).fill(subject)
  await bobMail.getByRole('textbox', { name: 'Message' }).fill(`Yarın ${word} ofisinde buluşalım.`)
  await bobMail.getByRole('dialog', { name: subject }).getByRole('button', { name: 'Send', exact: true }).click()
  await expect(bobMail.getByRole('button', { name: /^Send(ing…)?$/ })).toHaveCount(0, { timeout: 60_000 })
  await openWhenArrived(mail, new RegExp(subject))

  // The server searches subjects and addresses only.
  const folded = `golcuk${tag}`
  await search(mail, folded)
  await expect(mail.getByText('No matches')).toBeVisible({ timeout: 30_000 })

  // Turned on: asked first, then built.
  await mail.getByRole('button', { name: 'Advanced search' }).click()
  const form = mail.getByRole('form', { name: 'Advanced search' })
  await form.getByRole('button', { name: 'Enable' }).click()
  const ask = mail.getByRole('dialog', { name: 'Search message content?' })
  await expect(ask.getByText(/downloads a copy of your messages to this browser, encrypted/)).toBeVisible()
  await ask.getByRole('button', { name: 'Enable' }).click()
  await expect(form.getByRole('checkbox', { name: 'Search message content' })).toBeChecked({ timeout: 120_000 })
  await mail.keyboard.press('Escape')

  // Found in the text, by its folded word; the reader is told where from.
  await search(mail, folded)
  await expect(mail.getByRole('link', { name: new RegExp(subject) })).toBeVisible({ timeout: 60_000 })
  await expect(mail.getByText('Results include message text, searched in this browser.')).toBeVisible()
  // Nothing readable is kept: the database's records are sealed.
  const plain = await mail.evaluate(async (needle) => {
    const names = (await indexedDB.databases()).map((d) => d.name ?? '').filter((n) => n.startsWith('kutup-mail-search:'))
    for (const name of names) {
      const db = await new Promise<IDBDatabase>((resolve, reject) => {
        const r = indexedDB.open(name)
        r.onsuccess = () => resolve(r.result)
        r.onerror = () => reject(r.error)
      })
      const values = await new Promise<unknown[]>((resolve, reject) => {
        const r = db.transaction('records').objectStore('records').getAll()
        r.onsuccess = () => resolve(r.result)
        r.onerror = () => reject(r.error)
      })
      db.close()
      const text = values.map((v) => new TextDecoder('utf-8', { fatal: false }).decode(v as Uint8Array)).join(' ')
      if (text.includes(needle)) return true
    }
    return names.length === 0
  }, folded)
  expect(plain).toBe(false)

  // Deleted: the server's search again.
  await mail.goto(appUrl('mail', '/settings/general'))
  await mail.getByRole('button', { name: 'Delete local search data' }).click()
  await expect(mail.getByText('Local search data deleted.')).toBeVisible({ timeout: 30_000 })
  await mail.goto(appUrl('mail'))
  await expect(mail.getByRole('heading', { name: 'Inbox' })).toBeVisible({ timeout: 60_000 })
  await search(mail, folded)
  await expect(mail.getByText('No matches')).toBeVisible({ timeout: 30_000 })

  await aliceContext.close()
  await bobContext.close()
})
