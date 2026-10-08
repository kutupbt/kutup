import { expect, test } from '@playwright/test'
import { appOrigin, appUrl, newAccount, registerAccount } from '../fixtures/apps'

test('in Edit mode a code block reads as in Read mode until the cursor enters it', async ({ browser }) => {
  test.slow()
  const context = await browser.newContext({ viewport: { width: 1400, height: 900 } })
  await registerAccount(context, newAccount('notecode', 'Deneme123*NoteCodePassword'))
  const page = await context.newPage()
  await page.goto(appUrl('office'))
  await page.getByTestId('office-new-note').click()
  await page.waitForURL((url) => url.origin === appOrigin('drive') && url.pathname.startsWith('/file/'), { timeout: 60_000 })
  await expect(page.getByRole('link', { name: 'Back to Office' })).toBeVisible({ timeout: 120_000 })
  const content = page.locator('.cm-content').first()
  await content.click()
  await page.keyboard.press('Control+End')
  await page.keyboard.type('Above.\n\n```python title="greet.py"\ndef greet(name):\n    return name\n```\n\nBelow.', { delay: 5 })

  // The cursor is below it: the block is drawn, its fences hidden.
  const block = page.locator('.cm-lp-codeblock')
  await expect(block).toHaveCount(1)
  await expect(block.locator('.code-block-title')).toHaveText('greet.py')
  await expect(block.locator('.hljs-keyword').first()).toBeVisible()
  await expect(content).not.toContainText('```')

  // The keyboard reaches it: moving up into it shows its Markdown.
  await page.keyboard.press('ArrowUp')
  await page.keyboard.press('ArrowUp')
  await expect(block).toHaveCount(0)
  await expect(content).toContainText('```python title="greet.py"')

  // Leaving it draws it again; a click opens it for editing.
  await page.keyboard.press('Control+End')
  await expect(block).toHaveCount(1)
  await block.click()
  await expect(block).toHaveCount(0)
  await expect(content).toContainText('def greet(name):')

  // Read mode's text column is Edit mode's.
  const edit = await content.boundingBox()
  await page.getByRole('button', { name: 'Read', exact: true }).or(page.getByRole('radio', { name: 'Read' })).first().click()
  const read = await page.locator('.prose > .mx-auto').first().boundingBox()
  expect(Math.abs((read?.x ?? 0) - (edit?.x ?? 0))).toBeLessThanOrEqual(2)
  expect(Math.abs((read?.width ?? 0) - (edit?.width ?? 0))).toBeLessThanOrEqual(2)
  await context.close()
})
