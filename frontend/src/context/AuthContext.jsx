import { createContext, useContext, useMemo, useState } from 'react'
import { storage } from '../services/api'

const AuthContext = createContext(null)

/**
 * The platform has no sign-in or login: every visitor is the same full-access
 * operator. There is no session to create, restore or end - this context simply
 * exposes that operator so the capability checks across the UI resolve to
 * "allowed". The backend mirrors this by resolving token-less requests to the
 * same operator.
 */
const DEFAULT_OPERATOR = {
  id: 'operator',
  name: 'Operator',
  email: 'operator@cyberforecast.local',
  role: 'admin',
  fullAccess: true,
}

// Drop any session an older build may have left in this browser, so every
// visitor reliably resolves to the full-access operator (no stale token is
// ever attached to API requests).
storage.clear()

export function AuthProvider({ children }) {
  const [user, setUser] = useState(DEFAULT_OPERATOR)
  const capabilities = useMemo(() => new Set(user?.capabilities || []), [user])

  const value = useMemo(
    () => ({
      user,
      token: null,
      initializing: false,
      isAuthenticated: true,
      role: user?.role || null,
      capabilities,
      /** UI convenience only; the API enforces the real rule. */
      can: (capability) => (user?.fullAccess ? true : capabilities.has(capability)),
      hasRole: (...roles) => roles.includes(user?.role),
      updateUser: (patch) => setUser((current) => ({ ...(current || {}), ...(patch || {}) })),
    }),
    [capabilities, user],
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth() {
  const context = useContext(AuthContext)
  if (!context) throw new Error('useAuth must be used inside <AuthProvider>')
  return context
}
