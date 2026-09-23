/** Closed registry of Direct Chat suites implemented by this client. */
export const DIRECT_CHAT_SUITE = {
  PqxdhTripleRatchetV1: 1,
} as const

export type DirectChatSuiteId =
  (typeof DIRECT_CHAT_SUITE)[keyof typeof DIRECT_CHAT_SUITE]

/** Parse only suites this client can actually process. */
export function isDirectChatSuiteId(value: unknown): value is DirectChatSuiteId {
  return value === DIRECT_CHAT_SUITE.PqxdhTripleRatchetV1
}
