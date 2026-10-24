import { describe, expect, it } from 'vitest'
import { isDeviceBoundChatRoute } from './device-auth'

describe('isDeviceBoundChatRoute', () => {
  it('sends the device credential on device-bound Chat calls', () => {
    for (const url of [
      '/chat/keys',
      '/chat/manifest',
      '/chat/link-tokens',
      '/chat/provisioning/abc',
      '/chat/account-identity',
      '/chat/ws-ticket?deviceId=2',
      '/chat/device/2',
    ]) {
      expect(isDeviceBoundChatRoute(url, 'post'), url).toBe(true)
    }
    expect(isDeviceBoundChatRoute('/chat/device', 'get')).toBe(true)
  })

  it('never on the registration, the provisioning ticket, anonymous routes or other apps', () => {
    expect(isDeviceBoundChatRoute('/chat/device', 'post')).toBe(false)
    expect(isDeviceBoundChatRoute('/chat/device', 'POST')).toBe(false)
    expect(isDeviceBoundChatRoute('/chat/provisioning/ticket', 'post')).toBe(false)
    expect(isDeviceBoundChatRoute('/chat/anonymous/messages', 'post')).toBe(false)
    expect(isDeviceBoundChatRoute('/chat/anonymous/accounts/x/keys?server=a', 'post')).toBe(false)
    expect(isDeviceBoundChatRoute('/chat/anonymous/messages/multi', 'post')).toBe(false)
    expect(isDeviceBoundChatRoute('/drive/files', 'get')).toBe(false)
    expect(isDeviceBoundChatRoute(undefined, 'get')).toBe(false)
  })
})
