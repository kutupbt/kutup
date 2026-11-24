import { render } from '@testing-library/react'
import i18next, { type TFunction } from 'i18next'
import { beforeAll, describe, expect, it } from 'vitest'
import en from '../locales/en.json'
import { Linkified } from './linkify'
import { linkify } from './linkText'
import { closePopover, currentPopover, handOver, openPopover, popoverOpen } from './popoverState'
import { onceModel, type FrequencyModel } from './recurrence/frequency'
import { ruleText } from './recurrence/frequencyText'
import { reminderText } from './reminders/reminderText'
import { rangeView, shownDays, stepDate } from './viewState'

// The popovers' words and links, and the custom range the mini calendar
// opens (docs/plans/calendar.md, "Calendar UX parity").

const i18n = i18next.createInstance()
beforeAll(async () => {
  await i18n.init({ lng: 'en', resources: { en: { translation: en } }, interpolation: { escapeValue: false } })
})
const t: TFunction = ((...args: Parameters<TFunction>) => i18n.t(...args)) as TFunction

describe('links in a description (Proton’s urlify, safely)', () => {
  it('makes http, https and mailto links, and leaves the rest as text', () => {
    expect(linkify('Join https://meet.example/abc or mail mailto:a@b.example.')).toEqual([
      { kind: 'text', text: 'Join ' },
      { kind: 'link', text: 'https://meet.example/abc', href: 'https://meet.example/abc' },
      { kind: 'text', text: ' or mail ' },
      { kind: 'link', text: 'mailto:a@b.example', href: 'mailto:a@b.example' },
      { kind: 'text', text: '.' },
    ])
    expect(linkify('tel:+4412 sms:+1 file://x ftps://x javascript:alert(1) www.example.com')).toEqual([
      { kind: 'text', text: 'tel:+4412 sms:+1 file://x ftps://x javascript:alert(1) www.example.com' },
    ])
  })

  it('ends a link before closing punctuation and quotes, keeping balanced brackets', () => {
    expect(linkify('(see https://example.com/a_(b))').map((p) => p.text)).toEqual(['(see ', 'https://example.com/a_(b)', ')'])
    expect(linkify('"https://example.com/x",').map((p) => p.text)).toEqual(['"', 'https://example.com/x', '",'])
    expect(linkify('<https://example.com>').map((p) => p.text)).toEqual(['<', 'https://example.com', '>'])
  })

  it('writes markup as text and opens links without the page behind them', () => {
    const { container } = render(<Linkified text={'<img src=x onerror=alert(1)> <a href="javascript:x">y</a> https://ok.example/"><script>'} />)
    expect(container.querySelector('img, script')).toBeNull()
    const links = [...container.querySelectorAll('a')]
    expect(links.map((a) => a.getAttribute('href'))).toEqual(['https://ok.example/'])
    expect(links[0].getAttribute('rel')).toBe('noopener noreferrer')
    expect(links[0].getAttribute('target')).toBe('_blank')
    expect(container.textContent).toContain('<a href="javascript:x">y</a>')
  })

  it('makes no link of a scheme with nothing after it', () => {
    expect(linkify('https:// and mailto:')).toEqual([{ kind: 'text', text: 'https:// and mailto:' }])
  })
})

describe('a repeat in words (Proton’s getFrequencyString)', () => {
  // 2026-11-02 is a Monday; weeks start on Monday.
  const model = (change: Partial<FrequencyModel>): FrequencyModel => ({ ...onceModel('2026-11-02'), ...change })
  const text = (m: FrequencyModel, start = '2026-11-02', zone: string | null = 'Europe/Istanbul', viewZone = 'Europe/Istanbul') =>
    ruleText(t, { model: m, start, weekStart: 1, locale: 'en-GB', zone, viewZone })

  it('reads the presets', () => {
    expect(text(model({}))).toBe('')
    expect(text(model({ type: 'daily', frequency: 'daily' }))).toBe('Daily')
    expect(text(model({ type: 'weekly' }))).toBe('Weekly on Monday')
    expect(text(model({ type: 'monthly', frequency: 'monthly' }))).toBe('Monthly on day 2')
    expect(text(model({ type: 'monthly', frequency: 'monthly', monthly: 'onNthDay' }))).toBe('Monthly on the first Monday')
    expect(text(model({ type: 'monthly', frequency: 'monthly', monthly: 'onLastDay' }), '2026-11-30')).toBe('Monthly on the last Monday')
    expect(text(model({ type: 'yearly', frequency: 'yearly' }))).toBe('Yearly')
  })

  it('reads a custom rule: interval, days in the week’s order, its end', () => {
    expect(text(model({ type: 'custom', frequency: 'weekly', interval: 2, weeklyDays: [3, 1] }))).toBe('Every 2 weeks on Monday, Wednesday')
    expect(text(model({ type: 'custom', frequency: 'weekly', weeklyDays: [0, 1, 2, 3, 4, 5, 6] }))).toBe('Weekly on all days')
    expect(text(model({ type: 'custom', frequency: 'daily', interval: 3, ends: { type: 'count', count: 5, until: null } }))).toBe('Every 3 days, 5 times')
    expect(text(model({ type: 'custom', frequency: 'yearly', ends: { type: 'until', count: 2, until: '2030-01-01' } }))).toBe('Yearly, until 1 Jan 2030')
    expect(text(model({ type: 'custom', frequency: 'daily', ends: { type: 'count', count: 1, until: null } }))).toBe('Daily, 1 time')
  })

  it('names the series’ zone when its days depend on it and it isn’t the view’s', () => {
    expect(text(model({ type: 'weekly' }), '2026-11-02', 'America/New_York')).toBe('Weekly on Monday (America/New_York)')
    expect(text(model({ type: 'daily', frequency: 'daily' }), '2026-11-02', 'America/New_York')).toBe('Daily')
  })

  it('reads a rule the editor doesn’t make as Proton’s “Custom …”', () => {
    expect(text(model({ type: 'other', text: 'FREQ=MONTHLY;BYMONTHDAY=1,15' }))).toBe('Custom monthly')
    expect(text(model({ type: 'other', text: 'X-UNKNOWN' }))).toBe('Custom')
  })
})

describe('a reminder in words (Proton’s getNotificationString)', () => {
  const text = (trigger: string, allDay = false, type: 'device' | 'email' = 'device') => reminderText(t, { type, trigger }, allDay, 'en-GB', false)
  it('reads timed and all-day reminders', () => {
    expect(text('PT0S')).toBe('At time of event')
    expect(text('-PT15M')).toBe('15 minutes before')
    expect(text('-PT1H')).toBe('1 hour before')
    expect(text('-P2D')).toBe('2 days before')
    expect(text('-P1W', false, 'email')).toBe('1 week before by email')
    expect(text('PT9H', true)).toBe('On the same day at 9:00')
    expect(text('-PT15H', true)).toBe('1 day before at 9:00')
    expect(text('-P13DT15H', true)).toBe('2 weeks before at 9:00')
  })
})

describe('the custom range (Proton’s VIEWS.CUSTOM)', () => {
  it('opens a span of days as a week of them, of a week or more as a month of its weeks', () => {
    expect(rangeView('2026-11-03', '2026-11-05')).toEqual({ view: 'week', date: '2026-11-03', range: 2 })
    expect(rangeView('2026-11-03', '2026-11-03')).toEqual({ view: 'week', date: '2026-11-03', range: 0 })
    expect(rangeView('2026-11-02', '2026-11-15')).toEqual({ view: 'month', date: '2026-11-02', range: 1 })
    expect(rangeView('2026-11-01', '2026-12-31')).toEqual({ view: 'month', date: '2026-11-01', range: 5 })
  })

  it('shows the days of the range and steps by its length', () => {
    expect(shownDays('week', '2026-11-03', 2, 1)).toEqual(['2026-11-03', '2026-11-04', '2026-11-05'])
    expect(shownDays('month', '2026-11-04', 1, 1)).toHaveLength(14)
    expect(shownDays('month', '2026-11-04', 1, 1)[0]).toBe('2026-11-02')
    expect(shownDays('week', '2026-11-04', 0, 1)).toHaveLength(7)
    expect(stepDate('week', '2026-11-03', 2, 1)).toBe('2026-11-06')
    expect(stepDate('month', '2026-11-04', 1, -1)).toBe('2026-10-21')
    expect(stepDate('month', '2026-11-04', 0, 1)).toBe('2026-12-01')
  })
})

describe('the one popover and its focus (Proton’s PopoverContainer)', () => {
  it('opens one at a time and gives focus back where it opened from', () => {
    const chip = document.body.appendChild(document.createElement('button'))
    const other = document.body.appendChild(document.createElement('button'))
    chip.focus()
    openPopover({ kind: 'more', day: '2026-11-02' }, chip)
    expect(popoverOpen()).toBe(true)
    other.focus()
    closePopover(true)
    expect(popoverOpen()).toBe(false)
    expect(document.activeElement).toBe(chip)
  })

  it('leaves focus where a click outside put it, and hands over to a dialog from the opener', () => {
    const chip = document.body.appendChild(document.createElement('button'))
    const elsewhere = document.body.appendChild(document.createElement('button'))
    chip.focus()
    openPopover({ kind: 'more', day: '2026-11-02' }, chip)
    elsewhere.focus()
    closePopover(false)
    expect(document.activeElement).toBe(elsewhere)

    chip.focus()
    openPopover({ kind: 'more', day: '2026-11-02' }, chip)
    elsewhere.focus()
    let focusedWhenHanded: Element | null = null
    handOver(() => {
      focusedWhenHanded = document.activeElement
    })
    expect(focusedWhenHanded).toBe(chip)
    expect(currentPopover()).toBeNull()
  })

  it('keeps the return focus it is given (a day’s list opening one of its events)', () => {
    const more = document.body.appendChild(document.createElement('button'))
    const cell = document.body.appendChild(document.createElement('div'))
    openPopover({ kind: 'more', day: '2026-11-02' }, cell, more)
    expect(currentPopover()?.returnFocus).toBe(more)
    closePopover(true)
    expect(document.activeElement).toBe(more)
  })
})
