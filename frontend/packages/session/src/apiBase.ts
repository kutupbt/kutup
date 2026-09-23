// Resolves the API base the logic packages talk to.
//
// Every Kutup web app (account., drive., chat.) calls `/api` on its own
// origin; the reverse proxy routes it to the one kutup-server. The async +
// sync pair is kept so callers (axios, tus-js-client, raw fetch) share one
// accessor and a future non-web client can plug in a different base.

const API_BASE = '/api'

export async function resolveApiBase(): Promise<string> {
  return API_BASE
}

export function apiBase(): string {
  return API_BASE
}
