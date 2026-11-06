// API-key auth for the SPA. The key is stored per-browser; it is sent on every
// request, and a 401 surfaces a login overlay (see components/AuthGate).

const KEY = 'pahredar.apikey'
export const AUTH_REQUIRED_EVENT = 'pahredar:auth-required'

export function getApiKey(): string {
  try {
    return localStorage.getItem(KEY) || ''
  } catch {
    return ''
  }
}

export function setApiKey(k: string) {
  try {
    localStorage.setItem(KEY, k)
  } catch {
    /* ignore */
  }
}

export function clearApiKey() {
  try {
    localStorage.removeItem(KEY)
  } catch {
    /* ignore */
  }
}

// requireAuth signals that the API rejected the request for want of a key.
export function requireAuth() {
  window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT))
}
