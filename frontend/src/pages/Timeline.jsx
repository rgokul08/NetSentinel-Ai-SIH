import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  Activity,
  AlertOctagon,
  Clock,
  Download,
  Filter,
  Radar,
  RefreshCw,
  Search,
  ShieldAlert,
  Siren,
  Waves,
} from 'lucide-react'
import { trafficApi } from '../services/endpoints'
import { useApi } from '../hooks/useApi'
import { useToast } from '../context/ToastContext'
import {
  AttackBadge,
  Badge,
  Button,
  Card,
  EmptyState,
  ErrorState,
  KeyValue,
  LoadingState,
  Modal,
  SearchInput,
  Select,
  SeverityBadge,
  StatCard,
  Tabs,
} from '../components/ui'
import { downloadBlob, formatDateTime, formatNumber, formatPercent, formatTime, timeAgo, toCsv } from '../utils/format'
import { severityColor } from '../utils/theme'
import { SEVERITIES, WINDOWS } from '../utils/constants'
import { usePreferences } from '../hooks/usePreferences'

const EVENT_TYPES = [
  { value: 'attack', label: 'Attack detections', icon: ShieldAlert },
  { value: 'anomaly', label: 'Anomalies', icon: Activity },
  { value: 'alert', label: 'Alerts', icon: Siren },
  { value: 'forecast', label: 'Forecast runs', icon: Radar },
]

export default function Timeline() {
  const toast = useToast()
  const { prefs } = usePreferences()
  const [window_, setWindow] = useState(() => prefs.defaultWindow || '24h')
  const [limit, setLimit] = useState(200)
  const [type, setType] = useState('all')
  const [severity, setSeverity] = useState('')
  const [search, setSearch] = useState('')
  const [selected, setSelected] = useState(null)

  const state = useApi(() => trafficApi.timeline({ window: window_, limit }), [window_, limit], { keepPrevious: true })
  const events = state.data?.events || []
  const counts = state.data?.counts || {}

  const filtered = useMemo(() => {
    const needle = search.trim().toLowerCase()
    return events.filter((event) => {
      if (type !== 'all' && event.type !== type) return false
      if (severity && String(event.severity || '').toLowerCase() !== severity) return false
      if (!needle) return true
      return [event.title, event.attack_type, event.source_ip, event.destination_ip, event.detail?.protocol]
        .filter(Boolean)
        .some((value) => String(value).toLowerCase().includes(needle))
    })
  }, [events, severity, search, type])

  /** Group events by hour so the timeline reads like a SOC shift log. */
  const grouped = useMemo(() => {
    const buckets = new Map()
    filtered.forEach((event) => {
      const date = new Date(`${String(event.timestamp).endsWith('Z') ? event.timestamp : `${event.timestamp}Z`}`)
      const key = Number.isNaN(date.getTime()) ? 'undated' : `${date.toISOString().slice(0, 13)}:00:00Z`
      if (!buckets.has(key)) buckets.set(key, [])
      buckets.get(key).push(event)
    })
    return [...buckets.entries()].sort((a, b) => (a[0] === 'undated' ? 1 : b[0] === 'undated' ? -1 : new Date(b[0]) - new Date(a[0])))
  }, [filtered])

  const exportCsv = () => {
    if (!filtered.length) {
      toast.warning('Nothing to export', 'No events match the current filters.')
      return
    }
    const rows = filtered.map((event) => ({
      timestamp: event.timestamp,
      type: event.type,
      severity: event.severity,
      attack_type: event.attack_type,
      title: event.title,
      source_ip: event.source_ip,
      destination_ip: event.destination_ip,
      destination_port: event.destination_port,
      risk_score: event.risk_score,
      is_simulated: event.is_simulated,
      protocol: event.detail?.protocol,
      packets: event.detail?.packets,
      bytes: event.detail?.bytes,
    }))
    downloadBlob(toCsv(rows), `cyberforecast-timeline-${window_}.csv`, 'text/csv;charset=utf-8')
    toast.success('Timeline exported', `${rows.length} events written to CSV.`)
  }

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        {EVENT_TYPES.map((item) => (
          <StatCard
            key={item.value}
            label={item.label}
            value={formatNumber(counts[`${item.value}s`] ?? filtered.filter((event) => event.type === item.value).length)}
            icon={item.icon}
            tone={item.value === 'attack' ? 'red' : item.value === 'alert' ? 'amber' : item.value === 'anomaly' ? 'purple' : 'cyan'}
            loading={state.loading && !events.length}
            hint={type === item.value ? 'filter active — click to clear' : 'click to filter'}
            onClick={() => setType((current) => (current === item.value ? 'all' : item.value))}
          />
        ))}
      </div>

      <Card
        title="Event timeline"
        subtitle={`${formatNumber(filtered.length)} of ${formatNumber(events.length)} events · window ${window_} · grouped by hour`}
        icon={Clock}
        bodyClass="p-0"
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <Button size="sm" variant="ghost" icon={RefreshCw} onClick={state.refetch} loading={state.loading}>Refresh</Button>
            <Button size="sm" variant="secondary" icon={Download} onClick={exportCsv}>Export CSV</Button>
          </div>
        }
      >
        <div className="flex flex-wrap items-center gap-2 border-b border-slate-800/70 px-3 py-2.5">
          <Select className="w-auto min-w-[156px] py-1.5 text-[11px]" value={window_} onChange={(event) => setWindow(event.target.value)} options={WINDOWS} />
          <Select
            className="w-auto min-w-[132px] py-1.5 text-[11px]"
            value={limit}
            onChange={(event) => setLimit(Number(event.target.value))}
            options={[
              { value: 50, label: '50 events' },
              { value: 120, label: '120 events' },
              { value: 200, label: '200 events' },
              { value: 500, label: '500 events' },
            ]}
          />
          <Select className="w-auto min-w-[136px] py-1.5 text-[11px]" value={severity} placeholder="All severities" onChange={(event) => setSeverity(event.target.value)} options={SEVERITIES} />
          <SearchInput value={search} onChange={setSearch} placeholder="Search title, IP, attack…" className="w-56" />
          <Tabs
            className="ml-auto"
            value={type}
            onChange={setType}
            items={[{ value: 'all', label: 'All' }, ...EVENT_TYPES.map((item) => ({ value: item.value, label: item.label.split(' ')[0] }))]}
          />
        </div>

        {state.loading && !events.length ? (
          <LoadingState label="Loading timeline…" className="py-14" />
        ) : state.error && !events.length ? (
          <ErrorState error={state.error} onRetry={state.refetch} className="py-10" />
        ) : grouped.length === 0 ? (
          <EmptyState
            icon={Search}
            title="No events match these filters"
            message="Widen the window, clear the filters, or generate traffic from the simulation console."
            action={<Link to="/simulation"><Button variant="secondary" size="sm">Open simulation console</Button></Link>}
          />
        ) : (
          <div className="max-h-[70vh] overflow-y-auto px-4 py-3">
            {grouped.map(([hour, items]) => (
              <div key={hour} className="relative mb-5 pl-6">
                <span className="absolute left-0 top-1.5 h-2 w-2 rounded-full border border-cyan-400/60 bg-slate-950" />
                <span className="absolute left-[3.5px] top-4 h-full w-px bg-slate-800" />
                <p className="mono mb-2 text-[10.5px] uppercase tracking-[0.14em] text-slate-500">
                  {hour === 'undated' ? 'Undated events' : `${formatDateTime(hour)} · ${items.length} event(s)`}
                </p>
                <ul className="space-y-1.5">
                  {items.map((event) => {
                    const color = severityColor(event.severity).hex
                    const TypeIcon = event.type === 'attack' ? ShieldAlert : event.type === 'alert' ? Siren : event.type === 'forecast' ? Radar : Waves
                    return (
                      <li key={event.id}>
                        <button
                          type="button"
                          onClick={() => setSelected(event)}
                          className="flex w-full items-start gap-2.5 rounded-lg border border-slate-800/70 bg-slate-900/40 px-3 py-2 text-left transition hover:border-slate-700 hover:bg-slate-800/50"
                        >
                          <span className="mt-0.5 shrink-0 rounded-md border p-1" style={{ borderColor: `${color}55`, background: `${color}14`, color }}>
                            <TypeIcon size={12} />
                          </span>
                          <span className="min-w-0 flex-1">
                            <span className="flex flex-wrap items-center gap-1.5">
                              <span className="truncate text-[11.5px] font-medium text-slate-100">{event.title}</span>
                              {event.attack_type ? <AttackBadge type={event.attack_type} /> : null}
                              {event.severity ? <SeverityBadge severity={event.severity} /> : null}
                              {event.is_simulated ? <Badge tone="purple">simulated</Badge> : null}
                            </span>
                            <span className="mono mt-0.5 block truncate text-[10px] text-slate-500">
                              {formatTime(event.timestamp, { seconds: true })}
                              {event.source_ip ? ` · ${event.source_ip} → ${event.destination_ip || '—'}:${event.destination_port ?? '—'}` : ''}
                              {event.risk_score ? ` · risk ${formatPercent(event.risk_score, 0)}` : ''}
                              {event.detail?.protocol ? ` · ${event.detail.protocol}` : ''}
                            </span>
                          </span>
                          <span className="mono shrink-0 text-[10px] text-slate-600">{timeAgo(event.timestamp)}</span>
                        </button>
                      </li>
                    )
                  })}
                </ul>
              </div>
            ))}
          </div>
        )}
      </Card>

      <EventModal event={selected} onClose={() => setSelected(null)} />
    </div>
  )
}

function EventModal({ event, onClose }) {
  if (!event) return null
  return (
    <Modal open onClose={onClose} title={event.title} subtitle={`${formatDateTime(event.timestamp)} · ${event.type} event`} icon={AlertOctagon}>
      <div className="space-y-3">
        <div className="flex flex-wrap items-center gap-2">
          {event.attack_type ? <AttackBadge type={event.attack_type} /> : null}
          {event.severity ? <SeverityBadge severity={event.severity} /> : null}
          <Badge tone="slate">{event.type}</Badge>
          {event.is_simulated ? <Badge tone="purple">simulation data</Badge> : null}
        </div>
        <KeyValue
          columns={2}
          items={[
            { label: 'Source', value: event.source_ip ? `${event.source_ip}` : '—', mono: true },
            { label: 'Destination', value: event.destination_ip ? `${event.destination_ip}:${event.destination_port ?? ''}` : '—', mono: true },
            { label: 'Risk score', value: formatPercent(event.risk_score, 2), mono: true },
            { label: 'Protocol', value: event.detail?.protocol || '—' },
            { label: 'TCP flags', value: event.detail?.tcp_flags || '—', mono: true },
            { label: 'Packets', value: formatNumber(event.detail?.packets ?? 0), mono: true },
            { label: 'Bytes', value: formatNumber(event.detail?.bytes ?? 0), mono: true },
            { label: 'Packet rate', value: event.detail?.pps ? `${Number(event.detail.pps).toFixed(1)} pps` : '—', mono: true },
            { label: 'Model version', value: event.detail?.model_version || '—', mono: true },
            { label: 'Event id', value: event.id, mono: true },
          ]}
        />
        <div className="flex flex-wrap gap-2">
          {event.type === 'alert' && event.id ? (
            <Link to={`/alerts`}><Button variant="secondary" size="sm" icon={Siren}>Open triage queue</Button></Link>
          ) : null}
          <Link to="/traffic"><Button variant="ghost" size="sm" icon={Activity}>Inspect live traffic</Button></Link>
          {event.type === 'forecast' ? (
            <Link to="/forecast"><Button variant="ghost" size="sm" icon={Radar}>Open forecast</Button></Link>
          ) : null}
        </div>
        <p className="muted">
          Timeline events are assembled from persisted traffic records, alerts and forecast runs — nothing on this page is generated in the
          browser.
        </p>
      </div>
    </Modal>
  )
}
