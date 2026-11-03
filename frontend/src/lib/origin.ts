import { useEffect } from 'react'
import { useLocation } from 'react-router'

// Remembers the last list page (dashboard, explorer, news, vendor, …) with
// its filters, so a CVE page's breadcrumb leads back to exactly where the
// user came from instead of a bare explorer. Kept per browser tab.

const KEY = 'pahredar.origin'

export interface Origin {
  label: string
  to: string
}

// useOrigin records the current page as the origin while it is shown.
export function useOrigin(label: string | undefined) {
  const { pathname, search } = useLocation()
  useEffect(() => {
    if (!label) return
    try {
      sessionStorage.setItem(KEY, JSON.stringify({ label, to: pathname + search }))
    } catch {
      // Storage unavailable: breadcrumbs fall back to the explorer.
    }
  }, [label, pathname, search])
}

export function readOrigin(): Origin | null {
  try {
    const v = JSON.parse(sessionStorage.getItem(KEY) ?? 'null')
    return v && typeof v.label === 'string' && typeof v.to === 'string' && v.to.startsWith('/') ? v : null
  } catch {
    return null
  }
}
