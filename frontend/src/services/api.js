/**
 * HTTP client for the CyberForecast AI backend.
 *
 * The browser only ever calls same-origin `/api/...` paths: the Vite dev server
 * proxies them locally and Vercel rewrites them to the backend service in
 * production, so no backend URL or secret is ever baked into the bundle.
 */
import axios from 'axios'

export const TOKEN_KEY = 'cyberforecast.token'
export const USER_KEY = 'cyberforecast.user'

const BASE_URL = (import.meta.env.VITE_API_URL || '/api').replace(/\/$/, '')

export const storage = {
  getToken: () => {
    try {
      return localStorage.getItem(TOKEN_KEY)
    } catch {
      return null
    }
  },
  getUser: () => {
    try {
      const raw = localStorage.getItem(USER_KEY)
      return raw ? JSON.parse(raw) : null
    } catch {
      return null
    }
  },
  setSession: (token, user) => {
    try {
      localStorage.setItem(TOKEN_KEY, token)
      localStorage.setItem(USER_KEY, JSON.stringify(user || null))
    } catch {
      /* private browsing: session stays in memory only */
    }
  },
  clear: () => {
    try {
      localStorage.removeItem(TOKEN_KEY)
      localStorage.removeItem(USER_KEY)
    } catch {
      /* ignore */
    }
  },
}

const client = axios.create({
  baseURL: BASE_URL,
  timeout: 120000,
  headers: { 'Content-Type': 'application/json' },
})

client.interceptors.request.use((config) => {
  const token = storage.getToken()
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

/** Listeners invoked when the session expires so the app can redirect. */
const unauthorizedHandlers = new Set()
export function onUnauthorized(handler) {
  unauthorizedHandlers.add(handler)
  return () => unauthorizedHandlers.delete(handler)
}

/**
 * Normalise every failure into `{ message, status, errorType, requestId, fields }`
 * so pages can render one consistent error state.
 */
export function normalizeError(error) {
  const response = error?.response
  const data = response?.data
  const status = response?.status || (error?.code === 'ECONNABORTED' ? 408 : 0)

  let message = data?.detail || data?.message || error?.message || 'Request failed'
  if (typeof message !== 'string') message = JSON.stringify(message)
  if (status === 0) {
    message = 'Cannot reach the CyberForecast backend. Is the API server running?'
  } else if (status === 401) {
    message = data?.detail || 'Your session expired. Please sign in again.'
  } else if (status === 403) {
    message = data?.detail || 'Your role is not permitted to perform this action.'
  } else if (status === 422) {
    message = data?.detail || 'The request was rejected by validation.'
  } else if (status >= 500) {
    message = data?.detail || 'The backend encountered an internal error.'
  }

  return {
    message,
    status,
    errorType: data?.error_type || null,
    requestId: data?.request_id || null,
    fields: Array.isArray(data?.errors) ? data.errors : [],
  }
}

client.interceptors.response.use(
  (response) => response,
  (error) => {
    const normalized = normalizeError(error)
    if (normalized.status === 401 && storage.getToken()) {
      storage.clear()
      unauthorizedHandlers.forEach((handler) => {
        try {
          handler(normalized)
        } catch {
          /* ignore handler failures */
        }
      })
    }
    return Promise.reject(normalized)
  },
)

/** GET with query params, unwrapping `response.data`. */
export async function get(path, params, config) {
  const response = await client.get(path, { params: cleanParams(params), ...config })
  return response.data
}

/** POST/PUT/PATCH/DELETE helpers. */
export async function post(path, body, params, config) {
  const response = await client.post(path, body ?? {}, { params: cleanParams(params), ...config })
  return response.data
}

export async function put(path, body, params, config) {
  const response = await client.put(path, body ?? {}, { params: cleanParams(params), ...config })
  return response.data
}

export async function patch(path, body, params, config) {
  const response = await client.patch(path, body ?? {}, { params: cleanParams(params), ...config })
  return response.data
}

export async function del(path, params, config) {
  const response = await client.delete(path, { params: cleanParams(params), ...config })
  return response.data
}

/**
 * Upload a file as multipart/form-data.
 *
 * `fields` become extra form fields, `params` become query string parameters —
 * the FastAPI upload routes read their options (run_analysis, name, …) from the
 * query string, so callers must pass those through `params`.
 */
export async function upload(path, file, fields = {}, onProgress, params) {
  const form = new FormData()
  form.append('file', file)
  Object.entries(fields).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== '') form.append(key, String(value))
  })
  const response = await client.post(path, form, {
    params: cleanParams(params),
    headers: { 'Content-Type': 'multipart/form-data' },
    onUploadProgress: (event) => {
      if (onProgress && event.total) onProgress(Math.round((event.loaded * 100) / event.total))
    },
  })
  return response.data
}

/** Download a binary response and trigger a browser save. */
export async function download(path, fallbackFilename = 'download', params) {
  const response = await client.get(path, {
    params: cleanParams(params),
    responseType: 'blob',
  })
  const disposition = response.headers?.['content-disposition'] || ''
  const match = /filename\*?=(?:UTF-8'')?"?([^";]+)"?/i.exec(disposition)
  const filename = match ? decodeURIComponent(match[1]) : fallbackFilename
  const url = URL.createObjectURL(response.data)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  document.body.appendChild(link)
  link.click()
  link.remove()
  setTimeout(() => URL.revokeObjectURL(url), 4000)
  return filename
}

/** Strip undefined/null/'' so the backend sees only real filters. */
export function cleanParams(params) {
  if (!params) return undefined
  const out = {}
  Object.entries(params).forEach(([key, value]) => {
    if (value === undefined || value === null || value === '') return
    if (Array.isArray(value) && value.length === 0) return
    out[key] = value
  })
  return out
}

/**
 * Absolute WebSocket URL for the live traffic channel.
 *
 * `VITE_WS_URL` overrides everything (useful when the socket is served from a
 * different host or through a proxy that rewrites paths); otherwise the URL is
 * derived from the API base so split deployments (Vercel frontend + Render
 * backend) work with no extra configuration.
 */
export function websocketUrl(path = '/traffic/ws', token = storage.getToken()) {
  const override = (import.meta.env.VITE_WS_URL || '').replace(/\/$/, '')
  if (override) {
    const separator = override.includes('?') ? '&' : '?'
    return token ? `${override}${path.startsWith('/') ? path : `/${path}`}${separator}token=${encodeURIComponent(token)}` : `${override}${path.startsWith('/') ? path : `/${path}`}`
  }

  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  const base = BASE_URL.startsWith('http')
    ? BASE_URL.replace(/^http/, 'ws')
    : `${protocol}//${window.location.host}${BASE_URL}`
  const query = token ? `?token=${encodeURIComponent(token)}` : ''
  return `${base}${path}${query}`
}

export default client
