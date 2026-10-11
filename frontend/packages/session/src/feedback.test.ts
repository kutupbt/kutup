import { describe, expect, it } from 'vitest'
import { collectFeedbackDetails, feedbackIssueBody, githubIssueUrl } from './feedback'

describe('feedback', () => {
  it('collects the build, browser, language and window, never the page address', () => {
    window.history.pushState({}, '', '/c/direct%3Aalice%40kutup.dev?q=secret#key')
    const script = document.createElement('script')
    script.type = 'module'
    script.src = '/assets/index-BsTFsULO.js'
    document.head.append(script)
    const details = collectFeedbackDetails()
    expect(Object.keys(details).sort()).toEqual(['browser', 'language', 'screen', 'version'])
    expect(details.version).toBe('index-BsTFsULO')
    expect(JSON.stringify(details)).not.toMatch(/alice|secret|direct/)
    script.remove()
  })

  it('fills in a new-issue page on the tracker, labelled by kind', () => {
    const url = new URL(githubIssueUrl('kutupbt/kutup', { title: 'Upload stops', body: 'At 50%', kind: 'bug' }))
    expect(url.origin + url.pathname).toBe('https://github.com/kutupbt/kutup/issues/new')
    expect(url.searchParams.get('title')).toBe('Upload stops')
    expect(url.searchParams.get('body')).toBe('At 50%')
    expect(url.searchParams.get('labels')).toBe('bug')
    expect(new URL(githubIssueUrl('a/b', { title: 't', body: 'b', kind: 'feature' })).searchParams.get('labels')).toBe('enhancement')
    expect(new URL(githubIssueUrl('a/b', { title: 't', body: 'b', kind: 'other' })).searchParams.has('labels')).toBe(false)
    // A long report is cut to what GitHub accepts in an address.
    expect(new URL(githubIssueUrl('a/b', { title: 't', body: 'x'.repeat(10_000) })).searchParams.get('body')).toHaveLength(6000)
  })

  it('puts the details under the message in an issue', () => {
    expect(feedbackIssueBody('It broke', { browser: 'Firefox', language: '' })).toBe('It broke\n\n---\n- browser: Firefox')
    expect(feedbackIssueBody('It broke', null)).toBe('It broke')
  })
})
