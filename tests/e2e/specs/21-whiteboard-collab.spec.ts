import { expect, test } from '@playwright/test'
import { newAccount, openDrive, registerAccount } from '../fixtures/apps'
import { addImage, addRectangle, createWhiteboard, elementCount, hasImage, openWhiteboard } from '../fixtures/whiteboard'

const PASSWORD = 'Deneme123*WhiteboardCollabPassword'

test('a shape and a pasted image drawn in one tab reach the other', async ({ browser }) => {
  test.slow()
  const context = await browser.newContext()
  await registerAccount(context, newAccount('wbcollab', PASSWORD))
  const a = await openDrive(context)
  const url = await createWhiteboard(a)
  const b = await openWhiteboard(context, url)

  await addRectangle(a)
  await expect.poll(() => elementCount(b), { timeout: 30_000 }).toBe(1)

  // The image travels as an encrypted asset that tab B fetches and opens.
  await addImage(a)
  await expect.poll(() => hasImage(b), { timeout: 45_000 }).toBe(true)
  await context.close()
})
