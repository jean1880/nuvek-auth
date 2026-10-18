import { authFetch } from './fetch'
import { getCurrentAuth } from './useAuth'

/** Request a single-use, 30 s stream ticket (`POST /api/auth/ticket`). */
export async function getTicket(path = '/api/auth/ticket'): Promise<string> {
  const res = await authFetch(path, { method: 'POST' })
  if (!res.ok) throw new Error(`ticket request failed: ${res.status}`)
  const body = (await res.json()) as { ticket?: string }
  if (!body.ticket) throw new Error('ticket response had no ticket')
  return body.ticket
}

function sameOriginUrl(path: string): URL {
  const url = new URL(path, location.origin)
  if (url.origin !== location.origin) {
    throw new Error('ticket URLs are only built for same-origin paths')
  }
  return url
}

async function withTicket(path: string): Promise<URL> {
  const url = sameOriginUrl(path)
  const ctx = getCurrentAuth()
  if (!ctx || !ctx.enforced) return url
  await ctx.ready
  url.searchParams.set('ticket', await getTicket())
  // Mutated in place, never re-parsed from parts; re-assert the origin before returning.
  if (url.origin !== location.origin) {
    throw new Error('ticket URLs are only built for same-origin paths')
  }
  return url
}

/** `ws(s)://` same-origin URL with a fresh ticket. Call again on every reconnect. */
export async function authWebSocketUrl(path: string): Promise<string> {
  const url = await withTicket(path)
  url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:'
  return url.href
}

/** Same-origin URL with a fresh ticket, for `EventSource` and plain links. */
export async function authEventSourceUrl(path: string): Promise<string> {
  return (await withTicket(path)).href
}
