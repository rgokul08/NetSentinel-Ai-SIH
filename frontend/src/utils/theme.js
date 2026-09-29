/** Colour system for severities, attack classes and chart series. */

export const SEVERITY_COLORS = {
  critical: { text: 'text-rose-300', bg: 'bg-rose-500/12', border: 'border-rose-500/40', hex: '#fb7185', dot: 'bg-rose-400' },
  high: { text: 'text-orange-300', bg: 'bg-orange-500/12', border: 'border-orange-500/40', hex: '#fb923c', dot: 'bg-orange-400' },
  medium: { text: 'text-amber-300', bg: 'bg-amber-500/12', border: 'border-amber-500/40', hex: '#fbbf24', dot: 'bg-amber-400' },
  low: { text: 'text-sky-300', bg: 'bg-sky-500/12', border: 'border-sky-500/40', hex: '#38bdf8', dot: 'bg-sky-400' },
  informational: { text: 'text-slate-300', bg: 'bg-slate-500/12', border: 'border-slate-500/40', hex: '#94a3b8', dot: 'bg-slate-400' },
}

export const ATTACK_COLORS = {
  DDoS: '#f43f5e',
  DoS: '#fb923c',
  'Port Scan': '#fbbf24',
  'Brute Force': '#a855f7',
  'Bot Activity': '#22d3ee',
  Intrusion: '#f472b6',
  'Network Anomaly': '#818cf8',
  Benign: '#34d399',
}

export const ROLE_TONES = { admin: 'red', analyst: 'cyan', viewer: 'slate' }

export const CHART_PALETTE = ['#22d3ee', '#a855f7', '#fbbf24', '#fb7185', '#34d399', '#60a5fa', '#f472b6', '#facc15']

export const RISK_COLORS = {
  critical: '#fb7185',
  high: '#fb923c',
  medium: '#fbbf24',
  low: '#38bdf8',
  informational: '#94a3b8',
  none: '#475569',
}

export const STATUS_COLORS = {
  online: '#34d399',
  verified: '#34d399',
  ok: '#34d399',
  complete: '#34d399',
  running: '#22d3ee',
  paused: '#fbbf24',
  degraded: '#fbbf24',
  partial: '#fbbf24',
  pending: '#fbbf24',
  stopped: '#94a3b8',
  offline: '#fb7185',
  failed: '#fb7185',
  error: '#fb7185',
  unavailable: '#94a3b8',
}

export function severityColor(severity) {
  return SEVERITY_COLORS[String(severity || '').toLowerCase()] || SEVERITY_COLORS.informational
}

export function attackColor(attackType) {
  return ATTACK_COLORS[attackType] || '#64748b'
}

export function riskColor(level) {
  return RISK_COLORS[String(level || '').toLowerCase()] || RISK_COLORS.none
}

export function statusColor(status) {
  return STATUS_COLORS[String(status || '').toLowerCase()] || '#64748b'
}

/** Risk score (0-1) -> a readable level label used when the backend omits one. */
export function riskLevelFromScore(score) {
  const value = Number(score) || 0
  if (value >= 0.75) return 'critical'
  if (value >= 0.5) return 'high'
  if (value >= 0.28) return 'medium'
  if (value >= 0.12) return 'low'
  return 'informational'
}

export const AXIS_STYLE = { fontSize: 10, fill: '#64748b' }
export const GRID_COLOR = 'rgba(148,163,184,0.10)'
export const TOOLTIP_STYLE = {
  contentStyle: {
    background: 'rgba(2,6,23,0.96)',
    border: '1px solid #1e293b',
    borderRadius: 10,
    fontSize: 11,
    color: '#e2e8f0',
    boxShadow: '0 18px 40px -18px rgba(0,0,0,0.9)',
  },
  labelStyle: { color: '#94a3b8', fontSize: 10, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em' },
  itemStyle: { color: '#e2e8f0', fontSize: 11 },
}
