/** Presentation helpers shared by every page and chart. */

export function compactNumber(value, digits = 1) {
  const n = Number(value)
  if (!Number.isFinite(n)) return '0'
  const abs = Math.abs(n)
  if (abs >= 1e12) return `${(n / 1e12).toFixed(digits)}T`
  if (abs >= 1e9) return `${(n / 1e9).toFixed(digits)}B`
  if (abs >= 1e6) return `${(n / 1e6).toFixed(digits)}M`
  if (abs >= 1e3) return `${(n / 1e3).toFixed(digits)}K`
  if (abs >= 100) return n.toFixed(0)
  if (abs >= 1) return n.toFixed(digits)
  return n.toFixed(digits + 1)
}

export function formatNumber(value, digits = 0) {
  const n = Number(value)
  if (!Number.isFinite(n)) return '0'
  return n.toLocaleString('en-US', { maximumFractionDigits: digits, minimumFractionDigits: 0 })
}

export function formatPercent(value, digits = 1) {
  const n = Number(value)
  if (!Number.isFinite(n)) return '0%'
  return `${(n * 100).toFixed(digits)}%`
}

/** Accepts 0-1 or 0-100 style values and always renders a percentage. */
export function formatRatio(value, digits = 1) {
  const n = Number(value)
  if (!Number.isFinite(n)) return '0%'
  return `${(n <= 1 ? n * 100 : n).toFixed(digits)}%`
}

export function formatBytes(value, digits = 1) {
  const n = Number(value)
  if (!Number.isFinite(n) || n <= 0) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']
  const exponent = Math.min(Math.floor(Math.log(n) / Math.log(1024)), units.length - 1)
  return `${(n / 1024 ** exponent).toFixed(digits)} ${units[exponent]}`
}

export function formatDuration(seconds) {
  const n = Number(seconds)
  if (!Number.isFinite(n) || n <= 0) return '0s'
  if (n < 1) return `${(n * 1000).toFixed(0)} ms`
  if (n < 60) return `${n.toFixed(1)} s`
  const minutes = Math.floor(n / 60)
  const rest = Math.round(n % 60)
  if (minutes < 60) return `${minutes}m ${rest}s`
  const hours = Math.floor(minutes / 60)
  return `${hours}h ${minutes % 60}m`
}

export function parseTimestamp(value) {
  if (!value) return null
  if (value instanceof Date) return Number.isNaN(value.getTime()) ? null : value
  const text = String(value).trim()
  const normalized = text.endsWith('Z') || /[+-]\d{2}:?\d{2}$/.test(text) ? text : `${text}Z`
  const date = new Date(normalized)
  return Number.isNaN(date.getTime()) ? null : date
}

export function formatTime(value, options = {}) {
  const date = parseTimestamp(value)
  if (!date) return '-'
  return date.toLocaleTimeString('en-GB', {
    hour: '2-digit',
    minute: '2-digit',
    second: options.seconds ? '2-digit' : undefined,
    hour12: false,
  })
}

export function formatDateTime(value) {
  const date = parseTimestamp(value)
  if (!date) return '-'
  return `${date.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' })} ${formatTime(value)}`
}

export function formatAxisTime(value) {
  const date = parseTimestamp(value)
  if (!date) return ''
  return date.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', hour12: false })
}

export function formatAxisDate(value) {
  const date = parseTimestamp(value)
  if (!date) return ''
  return date.toLocaleDateString('en-GB', { day: '2-digit', month: 'short' })
}

export function timeAgo(value) {
  const date = parseTimestamp(value)
  if (!date) return '-'
  const seconds = Math.round((Date.now() - date.getTime()) / 1000)
  if (seconds < 5) return 'just now'
  if (seconds < 60) return `${seconds}s ago`
  const minutes = Math.round(seconds / 60)
  if (minutes < 60) return `${minutes}m ago`
  const hours = Math.round(minutes / 60)
  if (hours < 24) return `${hours}h ago`
  const days = Math.round(hours / 24)
  return `${days}d ago`
}

export function sinceLabel(value) {
  const date = parseTimestamp(value)
  if (!date) return 'never'
  return timeAgo(date)
}

export function truncate(value, length = 48) {
  const text = String(value ?? '')
  return text.length > length ? `${text.slice(0, length - 1)}…` : text
}

export function shortHash(value, head = 10, tail = 6) {
  const text = String(value ?? '')
  if (text.length <= head + tail + 1) return text
  return `${text.slice(0, head)}…${text.slice(-tail)}`
}

export function titleCase(value) {
  return String(value ?? '')
    .replace(/[_-]+/g, ' ')
    .replace(/\b\w/g, (character) => character.toUpperCase())
}

export function initials(name) {
  return String(name || '?')
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0].toUpperCase())
    .join('')
}

export function pluralize(count, singular, plural) {
  return `${formatNumber(count)} ${Number(count) === 1 ? singular : plural || `${singular}s`}`
}

export function clamp(value, min, max) {
  return Math.min(Math.max(Number(value) || 0, min), max)
}

export function downloadBlob(content, filename, type = 'text/plain;charset=utf-8') {
  const blob = content instanceof Blob ? content : new Blob([content], { type })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  document.body.appendChild(link)
  link.click()
  link.remove()
  setTimeout(() => URL.revokeObjectURL(url), 4000)
}

export function toCsv(rows, columns) {
  if (!rows?.length) return ''
  const keys = columns || Object.keys(rows[0])
  const escape = (value) => {
    const text = value === null || value === undefined ? '' : String(value)
    return /[",\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text
  }
  return [keys.join(','), ...rows.map((row) => keys.map((key) => escape(row[key])).join(','))].join('\n')
}

export function copyToClipboard(text) {
  if (navigator?.clipboard?.writeText) return navigator.clipboard.writeText(String(text))
  return new Promise((resolve, reject) => {
    try {
      const area = document.createElement('textarea')
      area.value = String(text)
      area.style.position = 'fixed'
      area.style.opacity = '0'
      document.body.appendChild(area)
      area.select()
      document.execCommand('copy')
      area.remove()
      resolve()
    } catch (error) {
      reject(error)
    }
  })
}

export function uniqueValues(rows, key) {
  return [...new Set((rows || []).map((row) => row?.[key]).filter((value) => value !== null && value !== undefined && value !== ''))]
}

export function groupSum(rows, groupKey, valueKey) {
  const totals = new Map()
  ;(rows || []).forEach((row) => {
    const group = row?.[groupKey] ?? 'unknown'
    totals.set(group, (totals.get(group) || 0) + Number(row?.[valueKey] || 0))
  })
  return [...totals.entries()].map(([name, value]) => ({ name, value })).sort((a, b) => b.value - a.value)
}

export function safeArray(value) {
  return Array.isArray(value) ? value : []
}

export function sum(values) {
  return safeArray(values).reduce((total, value) => total + (Number(value) || 0), 0)
}

export function mean(values) {
  const list = safeArray(values).map((value) => Number(value) || 0)
  return list.length ? list.reduce((total, value) => total + value, 0) / list.length : 0
}
