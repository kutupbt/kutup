import api from './client'
import { loadServerSettings } from './apps'

// Feedback from the sidebar of every app (docs/api.md, "Feedback"): sent to
// this server's administrators, who may forward it to the public tracker
// after reading it. Nothing goes to GitHub unless a person opens it there.

export type FeedbackKind = 'bug' | 'feature' | 'other'

/** What the form may add, each shown to the person before sending. */
export interface FeedbackDetails {
  version?: string
  browser?: string
  language?: string
  screen?: string
}

export interface FeedbackInput {
  kind: FeedbackKind
  /** The app it is sent from (`drive`, `chat`, `mail`, …). */
  app: string
  message: string
  details?: FeedbackDetails
}

export async function sendFeedback(input: FeedbackInput): Promise<void> {
  await api.post('/feedback', input)
}

/** The public tracker (`owner/repo` on GitHub), or null when the server has none. */
export async function feedbackTracker(): Promise<string | null> {
  const settings = await loadServerSettings<{ feedback?: { githubRepository?: string | null } }>()
  return settings.feedback?.githubRepository ?? null
}

/**
 * The technical details the form offers: which build, browser, language and
 * window size. Never where in the app the person is: a page's address can
 * name a file, a folder or the person they chat with.
 */
export function collectFeedbackDetails(): FeedbackDetails {
  const details: FeedbackDetails = {}
  // The build, by its main script's content-hashed name (`index-BsTFsULO`).
  const script = [...document.querySelectorAll<HTMLScriptElement>('script[type="module"][src]')]
    .map((s) => s.src.split('/').pop() ?? '')
    .find((name) => /^index-[\w-]+\.js$/.test(name))
  if (script) details.version = script.replace(/\.js$/, '')
  details.browser = navigator.userAgent.slice(0, 300)
  details.language = navigator.language
  details.screen = `${window.innerWidth}×${window.innerHeight}`
  return details
}

/** A new-issue page on the tracker, filled in; nothing is sent until the person submits it there. */
export function githubIssueUrl(repository: string, issue: { title: string; body: string; kind?: FeedbackKind }): string {
  const url = new URL(`https://github.com/${repository}/issues/new`)
  url.searchParams.set('title', issue.title.slice(0, 200))
  // GitHub refuses very long addresses; a long report is cut, not lost (it
  // stays with the administrators).
  url.searchParams.set('body', issue.body.slice(0, 6000))
  if (issue.kind === 'bug') url.searchParams.set('labels', 'bug')
  else if (issue.kind === 'feature') url.searchParams.set('labels', 'enhancement')
  return url.toString()
}

/** The issue text for feedback: the message, then its details. */
export function feedbackIssueBody(message: string, details?: FeedbackDetails | null): string {
  const lines = Object.entries(details ?? {})
    .filter(([, value]) => value)
    .map(([key, value]) => `- ${key}: ${value}`)
  return lines.length > 0 ? `${message}\n\n---\n${lines.join('\n')}` : message
}

/** Everything the sidebar's feedback form needs (`@kutup/ui/components/feedback`). */
export const feedbackServices = {
  sendFeedback,
  feedbackTracker,
  collectFeedbackDetails,
  githubIssueUrl,
  feedbackIssueBody,
}
