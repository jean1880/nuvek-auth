import { getCurrentAuth } from './useAuth'

/** Immutable absolute destination, captured before any await. */
function snapshot(input: RequestInfo | URL): string | null {
  const raw = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
  try {
    return new URL(raw, location.origin).href
  } catch {
    return null
  }
}

/**
 * `fetch` that attaches the bearer token when one exists. The token is never sent to a
 * cross-origin URL. The Response is returned as-is (callers handle 401/403).
 */
export async function authFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
  // Snapshot first: a caller-held URL could be mutated while we await the token. The
  // validated string is exactly what gets sent. (Request.url is already immutable.)
  const dest = snapshot(input)
  const target: RequestInfo | URL = input instanceof Request ? input : (dest ?? input)
  const ctx = getCurrentAuth()
  if (!ctx || !ctx.enforced || dest === null || new URL(dest).origin !== location.origin) {
    return fetch(target, init)
  }
  await ctx.ready
  const token = await ctx.getToken()
  if (!token) return fetch(target, init)
  const headers = new Headers(init?.headers ?? (input instanceof Request ? input.headers : undefined))
  headers.set('Authorization', `Bearer ${token}`)
  return fetch(target, { ...init, headers })
}
