import { useCallback, useSyncExternalStore } from 'react'

/**
 * Client-side interface preferences.
 *
 * These are cosmetic / ergonomic choices that belong to the browser profile, so
 * they are persisted in localStorage rather than the security backend. Every
 * preference below has a real effect somewhere in the app:
 *
 *  - liveUpdates    -> RealtimeContext opens (or keeps closed) the WebSocket
 *  - defaultWindow  -> initial time window on Traffic / Analytics / Forecast
 *  - reduceMotion   -> `.reduce-motion` on <html>, disabling CSS animation
 *  - tableDensity   -> `.density-compact` on <html>, tightening table padding
 */

const STORAGE_KEY = 'cyberforecast.preferences'

export const PREFERENCE_DEFAULTS = {
  liveUpdates: true,
  defaultWindow: '24h',
  reduceMotion: false,
  tableDensity: 'comfortable',
}

export const PREFERENCE_META = {
  liveUpdates: {
    label: 'Live updates',
    description: 'Keep the WebSocket feed open for real-time metrics, predictions and alerts.',
  },
  defaultWindow: {
    label: 'Default analysis window',
    description: 'Time range used when Traffic, Analytics and Forecast pages first load.',
  },
  reduceMotion: {
    label: 'Reduce motion',
    description: 'Disable animated pulses, arcs and transitions across the interface.',
  },
  tableDensity: {
    label: 'Table density',
    description: 'Compact fits more rows on screen; comfortable adds breathing room.',
  },
}

const listeners = new Set()
let cache = { ...PREFERENCE_DEFAULTS }

function readStorage() {
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY)
    if (!raw) return { ...PREFERENCE_DEFAULTS }
    const parsed = JSON.parse(raw)
    return { ...PREFERENCE_DEFAULTS, ...(parsed && typeof parsed === 'object' ? parsed : {}) }
  } catch {
    return { ...PREFERENCE_DEFAULTS }
  }
}

function applySideEffects(prefs) {
  const root = document.documentElement
  root.classList.toggle('reduce-motion', Boolean(prefs.reduceMotion))
  root.classList.toggle('density-compact', prefs.tableDensity === 'compact')
  root.dataset.defaultWindow = String(prefs.defaultWindow || '24h')
}

function load() {
  cache = readStorage()
  applySideEffects(cache)
}

function emit() {
  listeners.forEach((listener) => listener())
}

if (typeof window !== 'undefined') load()

function subscribe(listener) {
  listeners.add(listener)
  return () => listeners.delete(listener)
}

function getSnapshot() {
  return cache
}

export function getPreferences() {
  return cache
}

export function setPreference(key, value) {
  if (!(key in PREFERENCE_DEFAULTS)) return cache
  cache = { ...cache, [key]: value }
  try {
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(cache))
  } catch {
    /* private mode / quota: preferences stay in memory for this session */
  }
  applySideEffects(cache)
  emit()
  return cache
}

export function resetPreferences() {
  cache = { ...PREFERENCE_DEFAULTS }
  try {
    window.localStorage.removeItem(STORAGE_KEY)
  } catch {
    /* ignore */
  }
  applySideEffects(cache)
  emit()
  return cache
}

export function usePreferences() {
  const prefs = useSyncExternalStore(subscribe, getSnapshot, getSnapshot)

  const update = useCallback((key, value) => setPreference(key, value), [])
  const reset = useCallback(() => resetPreferences(), [])

  return { prefs, setPreference: update, resetPreferences: reset }
}

export default usePreferences
