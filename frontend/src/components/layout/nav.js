import {
  Activity,
  BarChart3,
  Boxes,
  Clock,
  Database,
  FileText,
  FlaskConical,
  Gauge,
  Globe2,
  LayoutDashboard,
  Lock,
  Radar,
  ScrollText,
  Settings2,
  ShieldCheck,
  Siren,
  SlidersHorizontal,
  Users,
} from 'lucide-react'

/**
 * Navigation model. `capability` mirrors the backend permission matrix so the
 * sidebar only shows what the signed-in role may actually open (the API still
 * enforces it independently).
 */
export const NAV_GROUPS = [
  {
    label: 'Overview',
    items: [
      { to: '/', label: 'Command Center', icon: LayoutDashboard, capability: 'dashboard.view', end: true },
      { to: '/analytics', label: 'Analytics', icon: BarChart3, capability: 'analytics.view' },
      { to: '/timeline', label: 'Event Timeline', icon: Clock, capability: 'traffic.view' },
      { to: '/threat-map', label: 'Threat Map', icon: Globe2, capability: 'traffic.view' },
    ],
  },
  {
    label: 'Detection & Forecasting',
    items: [
      { to: '/traffic', label: 'Live Traffic', icon: Activity, capability: 'traffic.view' },
      { to: '/detection', label: 'Detection Lab', icon: FlaskConical, capability: 'predict.run' },
      { to: '/forecast', label: 'Attack Forecast', icon: Radar, capability: 'forecast.view' },
    ],
  },
  {
    label: 'Response',
    items: [
      { to: '/alerts', label: 'Threat Alerts', icon: Siren, capability: 'alerts.view' },
      { to: '/reports', label: 'Reports', icon: FileText, capability: 'reports.view' },
    ],
  },
  {
    label: 'Intelligence',
    items: [
      { to: '/models', label: 'Model Registry', icon: Boxes, capability: 'models.view' },
      { to: '/datasets', label: 'Datasets', icon: Database, capability: 'traffic.view' },
      { to: '/blockchain', label: 'Integrity Ledger', icon: ShieldCheck, capability: 'blockchain.view' },
    ],
  },
  {
    label: 'Operations',
    items: [
      { to: '/simulation', label: 'Simulation Console', icon: SlidersHorizontal, capability: 'traffic.view' },
      { to: '/audit', label: 'Audit Log', icon: ScrollText, capability: 'audit.view' },
      { to: '/admin', label: 'Admin Console', icon: Users, capability: 'users.manage' },
      { to: '/settings', label: 'System & Profile', icon: Settings2, capability: 'profile.manage' },
    ],
  },
]

export const ROUTE_META = {
  '/': { title: 'Command Center', subtitle: 'Real-time posture, live detection and the next-hour attack forecast', icon: Gauge },
  '/analytics': { title: 'Analytics', subtitle: 'Trends, detection correctness and attacker behaviour', icon: BarChart3 },
  '/timeline': { title: 'Event Timeline', subtitle: 'Chronological view of detections, alerts and forecast runs', icon: Clock },
  '/threat-map': { title: 'Threat Map', subtitle: 'Source → destination attack geography and flow links', icon: Globe2 },
  '/traffic': { title: 'Live Traffic Monitor', subtitle: 'Streaming flows, throughput and protocol mix', icon: Activity },
  '/detection': { title: 'Detection Lab', subtitle: 'Run the ML pipeline on individual flows or batches', icon: FlaskConical },
  '/forecast': { title: 'Attack Forecast', subtitle: 'Probability of attack activity over configurable horizons', icon: Radar },
  '/alerts': { title: 'Threat Alerts', subtitle: 'Triage, assign and resolve security alerts', icon: Siren },
  '/reports': { title: 'Reports', subtitle: 'Generate and download PDF / CSV security reports', icon: FileText },
  '/models': { title: 'Model Registry', subtitle: 'Train, evaluate, compare and activate ML models', icon: Boxes },
  '/datasets': { title: 'Datasets', subtitle: 'Upload, profile and analyse network traffic datasets', icon: Database },
  '/blockchain': { title: 'Integrity Ledger', subtitle: 'Hash-anchored security events and tamper verification', icon: Lock },
  '/simulation': { title: 'Simulation Console', subtitle: 'Generate clearly-labelled synthetic attack traffic', icon: SlidersHorizontal },
  '/audit': { title: 'Audit Log', subtitle: 'Every privileged action, hash-chained for integrity', icon: ScrollText },
  '/admin': { title: 'Admin Console', subtitle: 'Users, platform statistics and runtime configuration', icon: Users },
  '/settings': { title: 'System & Profile', subtitle: 'Backend health, your account and security preferences', icon: Settings2 },
}
