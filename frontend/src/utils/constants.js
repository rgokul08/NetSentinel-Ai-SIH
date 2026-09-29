/** Domain constants mirrored from the backend (app/storage/schema.py, services). */

export const ATTACK_CLASSES = [
  'Benign',
  'DoS',
  'DDoS',
  'Port Scan',
  'Brute Force',
  'Bot Activity',
  'Intrusion',
  'Network Anomaly',
]

export const ATTACK_TYPES = ATTACK_CLASSES.filter((name) => name !== 'Benign')

export const SEVERITIES = ['informational', 'low', 'medium', 'high', 'critical']

export const ALERT_STATUSES = ['open', 'reviewed', 'resolved', 'false_positive']

export const ROLES = [
  { value: 'admin', label: 'Administrator', description: 'Full control over users, models, settings and audit logs.' },
  { value: 'analyst', label: 'Security Analyst', description: 'Operational access: datasets, training, forecasting, triage, reports.' },
  { value: 'viewer', label: 'Viewer', description: 'Read-only access to dashboards, analytics, alerts and reports.' },
]

export const WINDOWS = [
  { value: '5m', label: 'Last 5 minutes' },
  { value: '15m', label: 'Last 15 minutes' },
  { value: '1h', label: 'Last hour' },
  { value: '6h', label: 'Last 6 hours' },
  { value: '24h', label: 'Last 24 hours' },
  { value: '7d', label: 'Last 7 days' },
  { value: '30d', label: 'Last 30 days' },
]

export const FORECAST_HORIZONS = [5, 15, 30, 60]

export const SCENARIOS = [
  { key: 'mixed', label: 'Mixed campaign', icon: 'layers', description: 'Rotating attack mix - best for a full demo.' },
  { key: 'normal', label: 'Benign baseline', icon: 'activity', description: 'Healthy traffic only, used to confirm low false positives.' },
  { key: 'ddos', label: 'DDoS / volumetric flood', icon: 'waves', description: 'High packet-rate SYN floods against a target.' },
  { key: 'port_scan', label: 'Port scan / reconnaissance', icon: 'radar', description: 'Horizontal and vertical scanning across many ports.' },
  { key: 'brute_force', label: 'Brute force / credential stuffing', icon: 'key-round', description: 'Repeated failed authentications from few sources.' },
  { key: 'botnet', label: 'Botnet / C2 beaconing', icon: 'bot', description: 'Periodic low-volume beacons to command and control.' },
  { key: 'intrusion', label: 'Intrusion / exfiltration', icon: 'shield-alert', description: 'Long sessions with abnormal outbound byte ratios.' },
]

export const ALGORITHMS = [
  { key: 'random_forest', label: 'Random Forest', task: 'classification' },
  { key: 'gradient_boosting', label: 'Gradient Boosting (hist)', task: 'classification' },
  { key: 'logistic_regression', label: 'Logistic Regression', task: 'classification' },
  { key: 'extra_trees', label: 'Extra Trees', task: 'classification' },
  { key: 'decision_tree', label: 'Decision Tree', task: 'classification' },
  { key: 'isolation_forest', label: 'Isolation Forest', task: 'anomaly' },
]

export const PAGE_SIZES = [10, 25, 50, 100]

export const RISK_LEVELS = ['low', 'medium', 'high', 'critical']

export const DATA_ORIGIN_LABELS = {
  simulation: 'Simulation mode',
  dataset: 'Dataset ingest',
  mixed: 'Mixed sources',
  live: 'Live capture',
  none: 'No data yet',
}
