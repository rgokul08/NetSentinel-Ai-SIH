/**
 * Complete API surface of the CyberForecast backend, grouped by domain.
 *
 * Every entry mirrors a real FastAPI route (92 paths under `/api`); pages import
 * these instead of building URLs inline so call sites cannot drift from the API.
 */
import { del, download, get, patch, post, upload } from './api'

/* --- authentication & session ------------------------------------------- */
export const authApi = {
  login: (email, password, mfaCode) => post('/auth/login', { email, password, ...(mfaCode ? { mfa_code: mfaCode } : {}) }),
  mfaStatus: () => get('/auth/mfa/status'),
  mfaEnable: () => post('/auth/mfa/enable'),
  mfaConfirm: (code) => post('/auth/mfa/confirm', { code }),
  mfaDisable: (code) => post('/auth/mfa/disable', { code }),
  register: (payload) => post('/auth/register', payload),
  logout: () => post('/auth/logout'),
  me: () => get('/auth/me'),
  roles: () => get('/auth/roles'),
  changePassword: (payload) => post('/auth/change-password', payload),
  updateProfile: (payload) => patch('/auth/profile', payload),
  forgotPassword: (email) => post('/auth/forgot-password', { email }),
  resetPassword: (token, password) => post('/auth/reset-password', { token, password }),
}

/* --- platform health & configuration ------------------------------------- */
export const systemApi = {
  health: () => get('/health'),
  detailedHealth: () => get('/health/detailed'),
  config: () => get('/config'),
}

/* --- analytics ------------------------------------------------------------ */
export const analyticsApi = {
  dashboard: () => get('/analytics/dashboard'),
  overview: (params) => get('/analytics/overview', params),
  trends: (params) => get('/analytics/trends', params),
  entities: (params) => get('/analytics/top-entities', params),
}

/* --- live traffic --------------------------------------------------------- */
export const trafficApi = {
  live: (params) => get('/traffic/live', params),
  recent: (params) => get('/traffic/recent', params),
  summary: (params) => get('/traffic/summary', params),
  records: (params) => get('/traffic/records', params),
  timeline: (params) => get('/traffic/timeline', params),
  threatMap: (params) => get('/traffic/threat-map', params),
  streamEvents: (params) => get('/traffic/stream-events', params),
  analyze: (payload) => post('/traffic/analyze', payload),
}

/* --- detection / prediction ---------------------------------------------- */
export const predictApi = {
  predict: (flow) => post('/predict', { flow }),
  batch: (flows) => post('/predict/batch', { flows }),
  predictions: (params) => get('/predictions', params),
  prediction: (id) => get(`/predictions/${id}`),
  explain: () => get('/explain'),
}

/* --- attack forecasting --------------------------------------------------- */
export const forecastApi = {
  latest: () => get('/forecast/latest'),
  run: (payload) => post('/forecast', payload),
  history: (params) => get('/forecast/history', params),
  trend: (params) => get('/forecast/trend', params),
  options: () => get('/forecast/options'),
}

/* --- threat alerts -------------------------------------------------------- */
export const alertsApi = {
  list: (params) => get('/alerts', params),
  get: (id) => get(`/alerts/${id}`),
  update: (id, payload) => patch(`/alerts/${id}`, payload),
  stats: (params) => get('/alerts/stats', params),
  exportCsv: () => download('/alerts/export', 'cyberforecast-alerts.csv'),
}

/* --- model management ----------------------------------------------------- */
export const modelsApi = {
  list: (params) => get('/models', params),
  get: (id) => get(`/models/${id}`),
  algorithms: (task) => get('/models/algorithms', { task }),
  registry: () => get('/models/registry'),
  train: (payload) => post('/models/train', payload),
  activate: (id) => post(`/models/${id}/activate`),
  deactivate: (id) => post(`/models/${id}/deactivate`),
  validate: (id) => get(`/models/${id}/validate`),
  compare: (modelIds) => post('/models/compare', { model_ids: modelIds }),
  remove: (id) => del(`/models/${id}`),
  upload: (file, params, onProgress) => upload('/models/upload', file, {}, onProgress, params),
}

/* --- datasets ------------------------------------------------------------- */
export const datasetsApi = {
  list: (params) => get('/datasets', params),
  samples: () => get('/datasets/samples'),
  get: (id, params) => get(`/datasets/${id}`, params),
  preview: (id, params) => get(`/datasets/${id}/preview`, params),
  reprofile: (id) => post(`/datasets/${id}/profile`),
  upload: (file, params, onProgress) => upload('/datasets/upload', file, {}, onProgress, params),
  ingestSample: (name, params) => post(`/datasets/samples/${name}/ingest`, null, params),
  analyze: (id, params) => post(`/datasets/${id}/analyze`, null, params),
  train: (id, params) => post(`/datasets/${id}/train`, null, params),
  forecast: (id) => post(`/datasets/${id}/forecast`),
  download: (id, name) => download(`/datasets/${id}/download`, name || 'dataset.csv'),
  remove: (id) => del(`/datasets/${id}`),
}

/* --- blockchain integrity ------------------------------------------------- */
export const blockchainApi = {
  status: () => get('/blockchain/status'),
  stats: () => get('/blockchain/stats'),
  contract: () => get('/blockchain/contract'),
  events: (params) => get('/blockchain/events', params),
  event: (id) => get(`/blockchain/${id}`),
  record: (payload) => post('/blockchain/record', payload),
  verify: (payload) => post('/blockchain/verify', payload),
  verifyChain: (params) => post('/blockchain/verify-chain', null, params),
  retryPending: (params) => post('/blockchain/retry-pending', null, params),
}

/* --- reports -------------------------------------------------------------- */
export const reportsApi = {
  list: (params) => get('/reports', params),
  get: (id) => get(`/reports/${id}`),
  generate: (payload) => post('/reports/generate', payload),
  download: (id, name) => download(`/reports/${id}/download`, name || `report-${id}`),
  csv: (id, name) => download(`/reports/${id}/csv`, name || `report-${id}.csv`),
  remove: (id) => del(`/reports/${id}`),
}

/* --- audit log ------------------------------------------------------------ */
export const auditApi = {
  list: (params) => get('/audit-logs', params),
  categories: () => get('/audit-logs/categories'),
  verify: (params) => post('/audit-logs/verify', null, params),
  exportCsv: (params) => download('/audit-logs/export', 'cyberforecast-audit-log.csv', params),
}

/* --- simulation engine ---------------------------------------------------- */
export const simulationApi = {
  scenarios: () => get('/simulation/scenarios'),
  status: () => get('/simulation/status'),
  start: (params) => post('/simulation/start', null, params),
  stop: () => post('/simulation/stop'),
  pause: () => post('/simulation/pause'),
  resume: () => post('/simulation/resume'),
  inject: (params) => post('/simulation/inject', null, params),
  update: (params) => patch('/simulation', null, params),
}

/* --- administration ------------------------------------------------------- */
export const adminApi = {
  users: (params) => get('/admin/users', params),
  createUser: (payload) => post('/admin/users', payload),
  updateUser: (id, payload) => patch(`/admin/users/${id}`, payload),
  deleteUser: (id) => del(`/admin/users/${id}`),
  stats: () => get('/admin/stats'),
  health: () => get('/admin/health'),
  settings: () => get('/admin/settings'),
  updateSettings: (payload) => patch('/admin/settings', payload),
  seedStatus: () => get('/admin/seed/status'),
  reseed: (payload) => post('/admin/seed', payload || {}),
  resetDemo: () => post('/admin/reset-demo'),
}
