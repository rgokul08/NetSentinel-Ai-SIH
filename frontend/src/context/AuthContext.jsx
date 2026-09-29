import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { authApi } from '../services/endpoints'
import { onUnauthorized, storage } from '../services/api'

const AuthContext = createContext(null)

export function AuthProvider({ children }) {
  const [user, setUser] = useState(() => storage.getUser())
  const [token, setToken] = useState(() => storage.getToken())
  const [initializing, setInitializing] = useState(Boolean(storage.getToken()))
  const navigate = useNavigate()

  const persist = useCallback((nextToken, nextUser) => {
    setToken(nextToken || null)
    setUser(nextUser || null)
    if (nextToken) storage.setSession(nextToken, nextUser)
    else storage.clear()
  }, [])

  /** Validate a stored token on load so a stale session never renders the app. */
  useEffect(() => {
    let cancelled = false
    async function restore() {
      const stored = storage.getToken()
      if (!stored) {
        setInitializing(false)
        return
      }
      try {
        const profile = await authApi.me()
        if (!cancelled) persist(profile.access_token || stored, profile.user || profile)
      } catch {
        if (!cancelled) persist(null, null)
      } finally {
        if (!cancelled) setInitializing(false)
      }
    }
    restore()
    return () => {
      cancelled = true
    }
  }, [persist])

  /** Any 401 anywhere in the app signs the user out and returns to /login. */
  useEffect(
    () =>
      onUnauthorized(() => {
        persist(null, null)
        navigate('/login', { replace: true, state: { reason: 'session-expired' } })
      }),
    [navigate, persist],
  )

  const login = useCallback(
    async (email, password, mfaCode) => {
      const result = await authApi.login(email, password, mfaCode)
      // Backend signals a second-factor challenge instead of issuing a token.
      if (result?.require_mfa || !result?.access_token) {
        return { requireMfa: true, message: result?.mfa_message || 'Enter the code from your authenticator app.' }
      }
      persist(result.access_token, result.user)
      return result.user
    },
    [persist],
  )

  const register = useCallback(
    async (payload) => {
      const result = await authApi.register(payload)
      if (result?.access_token) {
        persist(result.access_token, result.user)
        return result.user
      }
      return result?.user || null
    },
    [persist],
  )

  const logout = useCallback(async () => {
    try {
      await authApi.logout()
    } catch {
      /* the local session is dropped regardless */
    }
    persist(null, null)
    navigate('/login', { replace: true })
  }, [navigate, persist])

  const refresh = useCallback(async () => {
    const profile = await authApi.me()
    const next = profile.user || profile
    setUser(next)
    storage.setSession(storage.getToken(), next)
    return next
  }, [])

  const capabilities = useMemo(() => new Set(user?.capabilities || []), [user])

  const value = useMemo(
    () => ({
      user,
      token,
      initializing,
      isAuthenticated: Boolean(token && user),
      role: user?.role || null,
      capabilities,
      /** Mirrors the backend permission matrix - UI convenience only, never trust. */
      can: (capability) => capabilities.has(capability),
      hasRole: (...roles) => roles.includes(user?.role),
      login,
      register,
      logout,
      refresh,
      updateUser: (patch) => {
        setUser((current) => {
          const next = { ...(current || {}), ...(patch || {}) }
          storage.setSession(storage.getToken(), next)
          return next
        })
      },
    }),
    [capabilities, initializing, login, logout, refresh, register, token, user],
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth() {
  const context = useContext(AuthContext)
  if (!context) throw new Error('useAuth must be used inside <AuthProvider>')
  return context
}
