import { useQuery, useQueryClient } from '@tanstack/react-query'
import { createContext, useContext, useEffect, useState, type ReactNode } from 'react'
import { api } from '../api/client'

// Session-cookie auth for the SPA. The browser holds an httpOnly session cookie
// (set by the server on login); this context exposes the current principal from
// /auth/me and gates the UI by role. A 401 from the API opens the login modal.

export type Role = 'anonymous' | 'viewer' | 'operator' | 'admin'
const RANK: Record<Role, number> = { anonymous: 0, viewer: 1, operator: 2, admin: 3 }

export const AUTH_REQUIRED_EVENT = 'pahredar:auth-required'

// requireAuth signals that the API rejected a request for want of a session.
export function requireAuth() {
  window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT))
}

interface AuthState {
  role: Role
  email: string
  isAuthenticated: boolean
  isLoading: boolean
  can: (min: Role) => boolean
  loginOpen: boolean
  openLogin: () => void
  closeLogin: () => void
  logout: () => Promise<void>
}

const Ctx = createContext<AuthState | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const qc = useQueryClient()
  const [loginOpen, setLoginOpen] = useState(false)
  const me = useQuery({ queryKey: ['me'], queryFn: api.me, staleTime: 5 * 60_000, retry: false })

  useEffect(() => {
    const onReq = () => setLoginOpen(true)
    window.addEventListener(AUTH_REQUIRED_EVENT, onReq)
    return () => window.removeEventListener(AUTH_REQUIRED_EVENT, onReq)
  }, [])

  const role = (me.data?.role ?? 'anonymous') as Role
  const value: AuthState = {
    role,
    email: me.data?.name ?? '',
    isAuthenticated: role !== 'anonymous',
    isLoading: me.isLoading,
    can: (min) => RANK[role] >= RANK[min],
    loginOpen,
    openLogin: () => setLoginOpen(true),
    closeLogin: () => setLoginOpen(false),
    logout: async () => {
      await api.logout()
      await qc.invalidateQueries() // refetch /auth/me (now anonymous) and drop private data
    },
  }
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>
}

export function useAuth(): AuthState {
  const v = useContext(Ctx)
  if (!v) throw new Error('useAuth must be used within an AuthProvider')
  return v
}
