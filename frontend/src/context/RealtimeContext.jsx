import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react'
import { useAuth } from './AuthContext'
import { websocketUrl } from '../services/api'
import { usePreferences } from '../hooks/usePreferences'

const RealtimeContext = createContext(null)
const MAX_BUFFER = 120

/**
 * Single shared WebSocket to `/api/traffic/ws`.
 *
 * The backend pushes `metrics`, `prediction`, `alert`, `forecast` and
 * `simulation_tick` frames; components subscribe by message type instead of
 * opening their own sockets. Reconnects with exponential backoff and pauses
 * automatically while the tab is hidden.
 */
export function RealtimeProvider({ children }) {
  const { token, isAuthenticated } = useAuth()
  const { prefs } = usePreferences()
  const liveUpdates = prefs.liveUpdates !== false
  const [status, setStatus] = useState('idle')
  const [lastMessage, setLastMessage] = useState(null)
  const [metrics, setMetrics] = useState([])
  const [events, setEvents] = useState([])
  const [alerts, setAlerts] = useState([])
  const [connectedAt, setConnectedAt] = useState(null)
  const [messageCount, setMessageCount] = useState(0)

  const socketRef = useRef(null)
  const subscribersRef = useRef(new Map())
  const retriesRef = useRef(0)
  const timerRef = useRef(null)
  const visibleRef = useRef(true)

  const subscribe = useCallback((type, handler) => {
    const key = type || '*'
    if (!subscribersRef.current.has(key)) subscribersRef.current.set(key, new Set())
    subscribersRef.current.get(key).add(handler)
    return () => subscribersRef.current.get(key)?.delete(handler)
  }, [])

  useEffect(() => {
    const onVisibility = () => {
      visibleRef.current = document.visibilityState === 'visible'
    }
    document.addEventListener('visibilitychange', onVisibility)
    return () => document.removeEventListener('visibilitychange', onVisibility)
  }, [])

  useEffect(() => {
    if (!isAuthenticated || !token) {
      setStatus('idle')
      return undefined
    }
    if (!liveUpdates) {
      // User preference: keep the socket closed until live updates are re-enabled.
      setStatus('paused')
      return undefined
    }

    let disposed = false

    const connect = () => {
      if (disposed) return
      setStatus((current) => (current === 'open' ? current : 'connecting'))
      let socket
      try {
        socket = new WebSocket(websocketUrl('/traffic/ws', token))
      } catch {
        setStatus('error')
        return
      }
      socketRef.current = socket

      socket.onopen = () => {
        if (disposed) return
        retriesRef.current = 0
        setStatus('open')
        setConnectedAt(new Date().toISOString())
      }

      socket.onmessage = (raw) => {
        if (disposed) return
        let message
        try {
          message = JSON.parse(raw.data)
        } catch {
          return
        }
        setLastMessage(message)
        setMessageCount((count) => count + 1)

        const type = message.type
        const payload = message.data ?? message
        if (type === 'metrics') {
          setMetrics((current) => [...current.slice(-MAX_BUFFER + 1), { ...payload, received_at: message.timestamp }])
        } else if (type === 'alert') {
          setAlerts((current) => [payload, ...current].slice(0, MAX_BUFFER))
        }
        if (type === 'prediction' || type === 'alert' || type === 'forecast' || type === 'simulation_tick') {
          setEvents((current) => [{ ...payload, type, received_at: message.timestamp || new Date().toISOString() }, ...current].slice(0, MAX_BUFFER))
        }

        subscribersRef.current.get(type)?.forEach((handler) => {
          try {
            handler(payload, message)
          } catch {
            /* a broken subscriber must not kill the stream */
          }
        })
        subscribersRef.current.get('*')?.forEach((handler) => {
          try {
            handler(payload, message)
          } catch {
            /* ignore */
          }
        })
      }

      socket.onerror = () => {
        if (!disposed) setStatus('error')
      }

      socket.onclose = () => {
        if (disposed) return
        socketRef.current = null
        setStatus('closed')
        const delay = Math.min(15000, 1000 * 2 ** Math.min(retriesRef.current, 4))
        retriesRef.current += 1
        timerRef.current = setTimeout(connect, delay)
      }
    }

    connect()
    const heartbeat = setInterval(() => {
      if (socketRef.current?.readyState === WebSocket.OPEN && visibleRef.current) {
        socketRef.current.send(JSON.stringify({ type: 'ping' }))
      }
    }, 25000)

    return () => {
      disposed = true
      clearInterval(heartbeat)
      if (timerRef.current) clearTimeout(timerRef.current)
      const socket = socketRef.current
      socketRef.current = null
      if (socket && socket.readyState <= WebSocket.OPEN) {
        socket.onclose = null
        socket.close()
      }
      setStatus('idle')
    }
  }, [isAuthenticated, liveUpdates, token])

  const send = useCallback((payload) => {
    if (socketRef.current?.readyState === WebSocket.OPEN) {
      socketRef.current.send(JSON.stringify(payload))
      return true
    }
    return false
  }, [])

  const value = useMemo(
    () => ({
      status,
      connected: status === 'open',
      pausedByPreference: !liveUpdates,
      connectedAt,
      messageCount,
      lastMessage,
      metrics,
      events,
      liveAlerts: alerts,
      subscribe,
      send,
      clearBuffers: () => {
        setMetrics([])
        setEvents([])
        setAlerts([])
      },
    }),
    [alerts, connectedAt, events, lastMessage, liveUpdates, messageCount, metrics, send, status, subscribe],
  )

  return <RealtimeContext.Provider value={value}>{children}</RealtimeContext.Provider>
}

export function useRealtime() {
  const context = useContext(RealtimeContext)
  if (!context) throw new Error('useRealtime must be used inside <RealtimeProvider>')
  return context
}
