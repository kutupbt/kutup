// Save to contacts from Chat, as Mail does: someone you chat with who is not
// in your address book gets a banner above the conversation (not a toast that
// is gone before it is read), saved in place with the shared dialog; the
// details panel then says they are in your contacts and links to them. A
// message request shows no banner until it is accepted, and a dismissed
// banner stays dismissed on this device.

import { expect, test, type Page } from '@playwright/test'
import { apiUrl, newAccount, registerAccount } from '../fixtures/apps'
import { acceptRequest, message, openChat, openConversationWith, openDirectChat, send } from '../fixtures/chat'

const PASSWORD = 'Deneme123*ChatSaveContactPassword'

function banner(page: Page) {
  return page.getByTestId('chat-not-in-contacts')
}

test('someone you chat with can be saved to contacts from the conversation', async ({ browser, request }) => {
  test.setTimeout(300_000)
  const { chat } = (await (await request.get(apiUrl('/auth/settings'))).json()) as { chat: { serverName: string } }
  const tag = Date.now()
  const alice = newAccount('chatsavealice', PASSWORD)
  const bob = newAccount('chatsavebob', PASSWORD)
  const contextA = await browser.newContext()
  const contextB = await browser.newContext()
  await registerAccount(contextA, alice)
  await registerAccount(contextB, bob)
  const pageA = await openChat(contextA)
  const pageB = await openChat(contextB)
  const bobAddress = `${bob.username}@${chat.serverName}`

  // Starting a chat with Bob: the banner is in the conversation, no toast.
  await openDirectChat(pageA, bobAddress)
  await expect(banner(pageA)).toContainText(`${bobAddress} is not in your contacts.`, { timeout: 60_000 })
  await expect(pageA.getByRole('button', { name: 'Add to contacts' })).toHaveCount(0)
  const hello = `hello-${tag}`
  await send(pageA, hello)

  // Bob's side is a request: accepted first, then offered.
  await openConversationWith(pageB, alice.username)
  await expect(message(pageB, hello)).toBeVisible({ timeout: 45_000 })
  await expect(banner(pageB)).toHaveCount(0)
  await acceptRequest(pageB)
  // Named as Chat names her (her username until she sets a display name).
  await expect(banner(pageB)).toContainText(`${alice.username} is not in your contacts.`, { timeout: 60_000 })
  // Dismissed, and still dismissed after a reload.
  await banner(pageB).getByRole('button', { name: 'Dismiss' }).click()
  await expect(banner(pageB)).toHaveCount(0)
  await pageB.reload()
  await openConversationWith(pageB, alice.username)
  await expect(message(pageB, hello)).toBeVisible({ timeout: 60_000 })
  await expect(banner(pageB)).toHaveCount(0)

  // Alice saves Bob from the banner, under a name of her choosing.
  await banner(pageA).getByRole('button', { name: 'Save to contacts' }).click()
  const dialog = pageA.getByRole('dialog', { name: 'Save to contacts' })
  await expect(dialog.getByRole('radio', { name: /New contact/ })).toHaveAttribute('aria-checked', 'true')
  await dialog.getByLabel('Name').fill('Bob Builder')
  await dialog.getByRole('button', { name: 'Save', exact: true }).click()
  await expect(pageA.getByText(`${bobAddress} saved to your contacts.`)).toBeVisible({ timeout: 60_000 })
  await expect(banner(pageA)).toHaveCount(0)

  // The details panel says so and links to the contact.
  await pageA.getByRole('button', { name: 'Chat details' }).click()
  const details = pageA.getByRole('region', { name: 'Chat details' })
  await expect(details.getByTestId('chat-in-contacts')).toContainText('In your contacts.')
  await expect(details.getByRole('link', { name: 'View contact' })).toHaveAttribute('href', /\/c\/[^/]+$/)
  await expect(details.getByTestId('chat-save-contact')).toHaveCount(0)

  // Bob, who dismissed the banner, can still save Alice from his details.
  await pageB.getByRole('button', { name: 'Chat details' }).click()
  await pageB.getByRole('region', { name: 'Chat details' }).getByTestId('chat-save-contact').click()
  await expect(pageB.getByRole('dialog', { name: 'Save to contacts' })).toBeVisible()

  await contextA.close()
  await contextB.close()
})
