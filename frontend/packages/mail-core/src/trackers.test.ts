import { describe, expect, it } from 'vitest'
import { trackerOf } from './trackers'

describe('trackerOf', () => {
  it('names known tracking pixels, as the server does', () => {
    expect(trackerOf('https://example.us1.list-manage.com/track/open.php?u=1')).toBe('Mailchimp')
    expect(trackerOf('https://u123.ct.sendgrid.net/wf/open?upn=x')).toBe('SendGrid')
    expect(trackerOf('https://r.us-east-1.awstrack.me/I0/0100/abc')).toBe('Amazon SES')
  })

  it('leaves real images and look-alikes alone', () => {
    expect(trackerOf('https://example.us1.list-manage.com/images/logo.png')).toBeNull()
    expect(trackerOf('https://notsendgrid.net/wf/open')).toBeNull()
    expect(trackerOf('not a url')).toBeNull()
  })
})
