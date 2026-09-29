import { useCallback, useEffect, useRef, useState } from 'react'

/**
 * Data fetching hook with loading / error / empty state built in.
 *
 * `loader` is re-run when `deps` change or when `refetch()` is called. Errors are
 * the normalised objects produced by the axios interceptor, so pages can render
 * `error.message` and `error.status` directly.
 */
export function useApi(loader, deps = [], options = {}) {
  const { enabled = true, initialData = null, keepPrevious = false, onError = null } = options
  const [data, setData] = useState(initialData)
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(Boolean(enabled))
  const [loadedAt, setLoadedAt] = useState(null)
  const mounted = useRef(true)
  const loaderRef = useRef(loader)
  const onErrorRef = useRef(onError)
  loaderRef.current = loader
  onErrorRef.current = onError

  useEffect(() => {
    mounted.current = true
    return () => {
      mounted.current = false
    }
  }, [])

  const run = useCallback(async () => {
    if (!enabled) return undefined
    setLoading(true)
    if (!keepPrevious) setError(null)
    try {
      const result = await loaderRef.current()
      if (!mounted.current) return result
      setData(result ?? null)
      setError(null)
      setLoadedAt(new Date().toISOString())
      return result
    } catch (failure) {
      if (!mounted.current) return undefined
      setError(failure)
      if (!keepPrevious) setData(initialData)
      onErrorRef.current?.(failure)
      return undefined
    } finally {
      if (mounted.current) setLoading(false)
    }
  }, [enabled, initialData, keepPrevious])

  useEffect(() => {
    run()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [enabled, ...deps])

  return {
    data,
    error,
    loading,
    loadedAt,
    isEmpty: !loading && !error && (data === null || data === undefined || (Array.isArray(data) && data.length === 0)),
    refetch: run,
    setData,
    setError,
  }
}

/** Poll a loader on an interval; pauses when the tab is hidden. */
export function usePoll(loader, intervalMs = 5000, options = {}) {
  const { enabled = true, deps = [], immediate = true } = options
  const state = useApi(loader, deps, { ...options, enabled })
  const timer = useRef(null)

  useEffect(() => {
    if (!enabled || !intervalMs) return undefined
    const tick = () => {
      if (document.visibilityState === 'visible') state.refetch()
    }
    timer.current = setInterval(tick, intervalMs)
    return () => clearInterval(timer.current)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [enabled, intervalMs, state.refetch])

  if (immediate === false) return state
  return state
}

/** Mutation helper for buttons that POST/PATCH: exposes run(), busy and error. */
export function useAction(action, options = {}) {
  const { onSuccess = null, onError = null } = options
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  const [result, setResult] = useState(null)
  const mounted = useRef(true)

  useEffect(() => {
    mounted.current = true
    return () => {
      mounted.current = false
    }
  }, [])

  const run = useCallback(
    async (...args) => {
      setBusy(true)
      setError(null)
      try {
        const value = await action(...args)
        if (mounted.current) setResult(value ?? null)
        onSuccess?.(value, ...args)
        return { ok: true, value }
      } catch (failure) {
        if (mounted.current) setError(failure)
        onError?.(failure, ...args)
        return { ok: false, error: failure }
      } finally {
        if (mounted.current) setBusy(false)
      }
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [action, onError, onSuccess],
  )

  return { run, busy, error, result, reset: () => { setError(null); setResult(null) } }
}

export function useDebounced(value, delay = 300) {
  const [debounced, setDebounced] = useState(value)
  useEffect(() => {
    const timer = setTimeout(() => setDebounced(value), delay)
    return () => clearTimeout(timer)
  }, [value, delay])
  return debounced
}

export function useInterval(callback, delay) {
  const saved = useRef(callback)
  useEffect(() => {
    saved.current = callback
  }, [callback])
  useEffect(() => {
    if (!delay) return undefined
    const id = setInterval(() => saved.current(), delay)
    return () => clearInterval(id)
  }, [delay])
}

/** Ticking clock used by "x seconds ago" labels so they stay honest. */
export function useNow(intervalMs = 15000) {
  const [now, setNow] = useState(() => Date.now())
  useInterval(() => setNow(Date.now()), intervalMs)
  return now
}
