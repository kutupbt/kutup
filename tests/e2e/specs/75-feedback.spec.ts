// Feedback from the sidebar of every app (docs/api.md, "Feedback"): it goes
// to this server's administrators, with only the technical details the form
// showed. An administrator forwards it to the public tracker by opening a
// prefilled GitHub issue (never naming who sent it), marks it done, or
// deletes it. Whoever prefers can open the GitHub issue from the form
// instead; nothing goes there unless they submit it on GitHub.

import { expect, test, type Page } from '@playwright/test'
import { apiUrl, appUrl, newAccount, openDrive, registerAccount, signInAsAdmin } from '../fixtures/apps'

const PASSWORD = 'Deneme123*FeedbackPassword'

async function send(page: Page, kind: string, message: string) {
  await page.getByTestId('feedback-open').click()
  const dialog = page.getByRole('dialog', { name: 'Send feedback' })
  await dialog.getByRole('combobox', { name: 'What is it about?' }).click()
  await page.getByRole('option', { name: kind }).click()
  await dialog.getByRole('textbox').fill(message)
  return dialog
}

test('feedback reaches the administrators, who can forward it to GitHub', async ({ browser, request }) => {
  test.slow()
  const settings = (await (await request.get(apiUrl('/auth/settings'))).json()) as { feedback: { githubRepository: string | null } }
  const repository = settings.feedback.githubRepository
  const tag = Date.now()
  const alice = newAccount('feedback', PASSWORD)
  const context = await browser.newContext()
  await registerAccount(context, alice)
  // GitHub is not reached from a test: its page is answered here, so the
  // prefilled address can be read.
  const fakeGitHub = (route: { fulfill: (r: { status: number; body: string }) => Promise<void> }) => route.fulfill({ status: 200, body: 'GitHub' })
  await context.route('https://github.com/**', fakeGitHub)
  const drive = await openDrive(context)

  // A bug, with the details the form shows (and nothing about where she is).
  const bug = `Upload stops at half ${tag}`
  let dialog = await send(drive, "Something isn't working", bug)
  const details = dialog.getByTestId('feedback-details')
  await expect(details).toContainText('Browser')
  await expect(details).toContainText('Window')
  await expect(details).not.toContainText('localhost')
  // The public route, if the server has a tracker: a prefilled issue page.
  if (repository) {
    const popup = context.waitForEvent('page')
    await dialog.getByRole('button', { name: 'Report on GitHub instead' }).click()
    const github = await popup
    await github.waitForURL(/^https:\/\/github\.com\//)
    const url = new URL(github.url())
    expect(url.origin + url.pathname).toBe(`https://github.com/${repository}/issues/new`)
    expect(url.searchParams.get('body')).toContain(bug)
    expect(url.searchParams.get('labels')).toBe('bug')
    await github.close()
  }
  await dialog.getByRole('button', { name: 'Send', exact: true }).click()
  await expect(drive.getByText('Thanks! Your feedback was sent to the administrators.')).toBeVisible({ timeout: 30_000 })

  // An idea, without details.
  const idea = `Dark mode for the editor ${tag}`
  dialog = await send(drive, 'An idea or feature request', idea)
  await dialog.getByLabel('Include technical details (shown below)').uncheck()
  await expect(dialog.getByTestId('feedback-details')).toHaveCount(0)
  await dialog.getByRole('button', { name: 'Send', exact: true }).click()
  await expect(drive.getByText('Thanks! Your feedback was sent to the administrators.').first()).toBeVisible({ timeout: 30_000 })

  // The administrator reads both.
  const admin = await browser.newContext()
  await admin.route('https://github.com/**', fakeGitHub)
  await signInAsAdmin(admin)
  const page = await admin.newPage()
  await page.goto(appUrl('account', '/admin/feedback'))
  const bugCard = page.getByTestId('feedback-item').filter({ hasText: bug })
  const ideaCard = page.getByTestId('feedback-item').filter({ hasText: idea })
  await expect(bugCard).toBeVisible({ timeout: 60_000 })
  await expect(bugCard).toContainText(alice.email)
  await expect(bugCard).toContainText('Drive')
  await expect(bugCard).toContainText('Browser')
  await expect(ideaCard).not.toContainText('Browser')

  // The idea is done.
  await ideaCard.getByRole('button', { name: 'Mark done' }).click()
  await expect(ideaCard).toBeHidden({ timeout: 30_000 })

  if (repository) {
    // The bug goes to GitHub: the issue names no one, and is linked back.
    const popup = admin.waitForEvent('page')
    await bugCard.getByRole('button', { name: 'Open on GitHub' }).click()
    const github = await popup
    await github.waitForURL(/^https:\/\/github\.com\//)
    const body = new URL(github.url()).searchParams.get('body') ?? ''
    expect(body).toContain(bug)
    expect(body).not.toContain(alice.email)
    await github.close()
    const forward = page.getByRole('dialog', { name: 'Forwarded to GitHub?' })
    await forward.getByLabel('Issue address (optional)').fill('https://example.org/issues/1')
    await expect(forward.getByRole('button', { name: 'Mark forwarded' })).toBeDisabled()
    await forward.getByLabel('Issue address (optional)').fill(`https://github.com/${repository}/issues/4242`)
    await forward.getByRole('button', { name: 'Mark forwarded' }).click()
  } else {
    await bugCard.getByRole('button', { name: 'Mark done' }).click()
  }
  await expect(bugCard).toBeHidden({ timeout: 30_000 })

  await page.getByRole('tab', { name: 'Resolved' }).click()
  const resolvedBug = page.getByTestId('feedback-item').filter({ hasText: bug })
  await expect(resolvedBug).toContainText(repository ? 'Forwarded' : 'Done', { timeout: 30_000 })
  if (repository) await expect(resolvedBug.getByRole('link', { name: `${repository}/issues/4242` })).toBeVisible()
  await expect(page.getByTestId('feedback-item').filter({ hasText: idea })).toContainText('Done')

  // Deleted for good.
  await resolvedBug.getByRole('button', { name: 'Delete' }).click()
  await page.getByRole('alertdialog').getByRole('button', { name: 'Delete' }).click()
  await expect(resolvedBug).toBeHidden({ timeout: 30_000 })

  await admin.close()
  await context.close()
})
