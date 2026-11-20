// The release this web build belongs to (docs/plans/api-surface.md §1.2):
// what `X-Kutup-Client` names beside the app's client type, and what the
// server compares with its minimum for that type.

declare const __KUTUP_RELEASE__: string | undefined

export const RELEASE: string = typeof __KUTUP_RELEASE__ === 'string' ? __KUTUP_RELEASE__ : '0.0.0-dev'

/** `X-Kutup-Client`'s value for `clientType`: `<clientType>/<release>`. */
export function clientHeader(clientType: string): string {
  return `${clientType}/${RELEASE}`
}
