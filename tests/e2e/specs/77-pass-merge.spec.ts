import { expect, test } from '@playwright/test'
import { newAccount, registerAccount, signIn } from '../fixtures/apps'
import { addEntry, createVault, editEntry, expectSaved, openEntry, openPass, shownValue } from '../fixtures/pass'

const PASSWORD = 'Deneme123*PassMergeAccount'

test('pass: two devices editing one vault apart lose nothing; a field changed on both is marked for review', async ({ browser }) => {
  test.slow()
  const account = newAccount('pass77', PASSWORD)
  const laptop = await browser.newContext()
  await registerAccount(laptop, account)
  const a = await laptop.newPage()
  await openPass(a)
  const vaultUrl = await createVault(a, 'Ortak', 'kasa-77-parola')
  await addEntry(a, { title: 'Posta', userName: 'ayse', password: 'p0', notes: 'ilk not' })
  await expectSaved(a)

  // The phone opens the same vault (its key kept in the account).
  const phone = await browser.newContext()
  await signIn(phone, account)
  const b = await phone.newPage()
  await b.goto(vaultUrl)
  await expect(b.getByRole('heading', { name: 'Ortak', exact: true, level: 1 })).toBeVisible({ timeout: 60_000 })
  await openEntry(b, 'Posta')

  // Disjoint edits: the laptop's password, the phone's user name.
  await editEntry(a, 'Posta', { password: 'laptop-parola' })
  await expectSaved(a)
  await editEntry(b, 'Posta', { userName: 'ayse.telefon' })
  // The phone's save meets the laptop's and merges.
  await expectSaved(b)
  await expect(shownValue(b, 'Posta', 'User name')).toHaveText('ayse.telefon')
  const phoneEntry = b.getByRole('article', { name: 'Posta' })
  await phoneEntry.getByRole('button', { name: 'Show password' }).click()
  await expect(phoneEntry.getByText('laptop-parola')).toBeVisible()

  await a.reload()
  await openEntry(a, 'Posta')
  await expect(shownValue(a, 'Posta', 'User name')).toHaveText('ayse.telefon')

  // The same field on both: one value shown, the other in history, marked for review.
  await editEntry(a, 'Posta', { notes: 'laptop notu' })
  await expectSaved(a)
  await editEntry(b, 'Posta', { notes: 'telefon notu' })
  await expectSaved(b)
  await expect(b.getByText('Merged with another device')).toBeVisible()
  await expect(b.getByRole('list', { name: 'Entries' }).getByText('Review')).toBeVisible()
  const review = b.getByRole('article', { name: 'Posta' })
  await expect(review.getByText('Changed on two devices')).toBeVisible()
  await review.getByRole('button', { name: 'See history' }).click()
  const history = b.getByRole('dialog', { name: 'Earlier versions' })
  // The laptop's note is one of the earlier versions.
  const shows = history.getByRole('button', { name: 'Show' })
  await expect(shows.first()).toBeVisible()
  let found = false
  for (let i = 0; i < (await shows.count()) && !found; i++) {
    await shows.nth(i).click()
    found = await history.getByText('laptop notu').isVisible()
    if (!found) await history.getByRole('button', { name: 'Hide' }).click()
  }
  expect(found).toBe(true)
  await history.getByRole('button', { name: 'Close' }).click()
  await review.getByRole('button', { name: 'Mark as reviewed' }).click()
  await expect(review.getByText('Changed on two devices')).toBeHidden()
  await expectSaved(b)

  await laptop.close()
  await phone.close()
})
