import { useMemo, useState } from 'react'
import {
  ArrowRight,
  Eye,
  EyeOff,
  Globe2,
  Info,
  Layers,
  Radar,
  RefreshCw,
  Server,
  ShieldAlert,
  Target,
} from 'lucide-react'
import { trafficApi } from '../services/endpoints'
import { useApi } from '../hooks/useApi'
import { useAuth } from '../context/AuthContext'
import {
  AttackBadge,
  Badge,
  Button,
  Card,
  DataTable,
  EmptyState,
  ErrorState,
  LoadingState,
  Progress,
  Select,
  StatCard,
  Switch,
} from '../components/ui'
import { compactNumber, formatBytes, formatNumber, formatPercent, timeAgo } from '../utils/format'
import { attackColor, riskColor } from '../utils/theme'
import { WINDOWS } from '../utils/constants'
import { usePreferences } from '../hooks/usePreferences'

/** Stylised region anchors. Regions are a deterministic abstraction of source IPs, not geolocation. */
const REGION_POINTS = {
  'North America': { x: 195, y: 165 },
  'South America': { x: 300, y: 350 },
  'Western Europe': { x: 478, y: 152 },
  'Northern Europe': { x: 520, y: 104 },
  'Eastern Europe': { x: 573, y: 143 },
  'Middle East': { x: 612, y: 212 },
  Africa: { x: 512, y: 300 },
  'South Asia': { x: 682, y: 243 },
  'East Asia': { x: 792, y: 172 },
  'South-East Asia': { x: 806, y: 292 },
  Oceania: { x: 866, y: 392 },
  Unknown: { x: 500, y: 462 },
}

/** Very rough continent silhouettes - purely decorative backdrop. */
const CONTINENTS = [
  'M95,120 L180,86 L268,104 L300,150 L262,196 L214,232 L176,214 L132,190 L96,168 Z',
  'M262,268 L318,262 L344,318 L330,392 L296,432 L268,392 L254,330 Z',
  'M446,116 L520,96 L566,118 L556,164 L500,190 L456,176 L438,146 Z',
  'M470,214 L556,206 L588,254 L566,332 L520,372 L486,320 L466,262 Z',
  'M586,120 L700,96 L806,120 L860,164 L820,206 L742,196 L668,214 L612,182 Z',
  'M660,232 L742,222 L806,258 L818,318 L770,344 L706,318 L668,278 Z',
  'M826,352 L900,344 L932,388 L900,428 L846,414 L820,382 Z',
]

const WINDOW_OPTIONS = WINDOWS.filter((item) => ['1h', '6h', '24h', '7d'].includes(item.value))

export default function ThreatMap() {
  const { user } = useAuth()
  const { prefs } = usePreferences()
  const [window_, setWindow] = useState(() => prefs.defaultWindow || '24h')
  const [limit, setLimit] = useState(60)
  const [showBenign, setShowBenign] = useState(false)
  const [hoverLink, setHoverLink] = useState(null)
  const [selectedRegion, setSelectedRegion] = useState(null)

  const state = useApi(() => trafficApi.threatMap({ window: window_, limit }), [window_, limit], { keepPrevious: true })
  const data = state.data

  const regionStats = useMemo(() => data?.regions || [], [data])
  const nodes = useMemo(() => data?.nodes || [], [data])
  const links = useMemo(() => (showBenign ? data?.links || [] : (data?.links || []).filter((link) => link.is_attack)), [data, showBenign])

  const totals = useMemo(() => {
    const flows = regionStats.reduce((total, region) => total + Number(region.flows || 0), 0)
    const attacks = regionStats.reduce((total, region) => total + Number(region.attacks || 0), 0)
    const packets = regionStats.reduce((total, region) => total + Number(region.packets || 0), 0)
    const attackLinks = (data?.links || []).filter((link) => link.is_attack).length
    return { flows, attacks, packets, attackLinks, regions: regionStats.length }
  }, [data, regionStats])

  const maxLinkWeight = useMemo(() => Math.max(1, ...links.map((link) => Number(link.packets || link.flows || 1))), [links])

  const pointFor = (region) => REGION_POINTS[region] || REGION_POINTS.Unknown

  if (state.loading && !data) return <LoadingState label="Rendering threat map…" className="py-24" />
  if (state.error && !data) return <ErrorState error={state.error} onRetry={state.refetch} className="py-16" />

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
        <StatCard label="Regions involved" value={formatNumber(totals.regions)} icon={Globe2} tone="cyan" hint={`${formatNumber(nodes.length)} endpoints mapped`} />
        <StatCard label="Flows mapped" value={formatNumber(totals.flows)} icon={Layers} tone="green" hint={`${compactNumber(totals.packets)} packets`} />
        <StatCard label="Attack flows" value={formatNumber(totals.attacks)} icon={ShieldAlert} tone="red" hint={`${formatNumber(totals.attackLinks)} attack links drawn`} />
        <StatCard label="Attack share" value={formatPercent(totals.flows ? totals.attacks / totals.flows : 0, 1)} icon={Radar} tone="amber" />
        <StatCard label="Privacy mode" value={user?.role === 'viewer' ? 'Masked' : 'Full IPs'} icon={user?.role === 'viewer' ? EyeOff : Eye} tone="purple" hint={data?.privacy ? 'regions are synthetic abstractions' : ''} />
      </div>

      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_340px]">
        <Card
          title="Attack geography"
          subtitle={`Source → destination links over the ${window_} window · ${links.length} shown`}
          icon={Globe2}
          actions={
            <div className="flex flex-wrap items-center gap-2">
              <Select className="w-auto min-w-[148px] py-1.5 text-[11px]" value={window_} onChange={(event) => setWindow(event.target.value)} options={WINDOW_OPTIONS} />
              <Select
                className="w-auto min-w-[124px] py-1.5 text-[11px]"
                value={limit}
                onChange={(event) => setLimit(Number(event.target.value))}
                options={[
                  { value: 20, label: 'Top 20 links' },
                  { value: 40, label: 'Top 40 links' },
                  { value: 60, label: 'Top 60 links' },
                  { value: 120, label: 'Top 120 links' },
                ]}
              />
              <Button size="sm" variant="ghost" icon={RefreshCw} onClick={state.refetch} loading={state.loading}>Refresh</Button>
            </div>
          }
        >
          <div className="rounded-xl border border-slate-800 bg-[#060a11] p-2">
            <svg viewBox="0 0 1000 520" className="h-[380px] w-full sm:h-[460px]" role="img" aria-label="Stylised threat map of attack flows between abstracted regions">
              <defs>
                <radialGradient id="map-glow" cx="50%" cy="45%" r="60%">
                  <stop offset="0%" stopColor="rgba(34,211,238,0.10)" />
                  <stop offset="100%" stopColor="rgba(2,6,23,0)" />
                </radialGradient>
                <filter id="map-blur" x="-50%" y="-50%" width="200%" height="200%">
                  <feGaussianBlur stdDeviation="6" />
                </filter>
              </defs>

              <rect width="1000" height="520" fill="url(#map-glow)" />
              {CONTINENTS.map((path, index) => (
                <path key={index} d={path} fill="rgba(51,65,85,0.28)" stroke="rgba(100,116,139,0.35)" strokeWidth="1" />
              ))}

              {/* links */}
              {links.map((link, index) => {
                const from = pointFor(link.source_region)
                const to = pointFor(REGION_POINTS[link.target_region] ? link.target_region : 'Unknown')
                const weight = Number(link.packets || link.flows || 1)
                const thickness = 0.6 + (weight / maxLinkWeight) * 4.4
                const midX = (from.x + to.x) / 2
                const midY = Math.min(from.y, to.y) - Math.abs(to.x - from.x) * 0.22 - 26
                const color = link.is_attack ? attackColor(link.attack_type) : '#475569'
                const active = hoverLink?.source === link.source && hoverLink?.target === link.target
                return (
                  <g key={`${link.source}-${link.target}-${index}`}>
                    <path
                      d={`M ${from.x} ${from.y} Q ${midX} ${midY} ${to.x} ${to.y}`}
                      fill="none"
                      stroke={color}
                      strokeWidth={active ? thickness + 1.4 : thickness}
                      strokeOpacity={active ? 0.95 : link.is_attack ? 0.62 : 0.22}
                      className={link.is_attack ? 'flow-dash' : undefined}
                      onMouseEnter={() => setHoverLink(link)}
                      onMouseLeave={() => setHoverLink(null)}
                      style={{ cursor: 'pointer' }}
                    />
                  </g>
                )
              })}

              {/* region nodes */}
              {regionStats.map((region) => {
                const point = pointFor(region.region)
                const radius = 7 + Math.min(26, Math.sqrt(Number(region.flows || 1)) * 1.15)
                const hex = riskColor(region.risk >= 0.5 ? 'critical' : region.risk >= 0.28 ? 'medium' : 'low')
                const active = selectedRegion === region.region
                return (
                  <g key={region.region} onClick={() => setSelectedRegion(active ? null : region.region)} style={{ cursor: 'pointer' }}>
                    {region.attacks > 0 ? (
                      <circle cx={point.x} cy={point.y} r={radius} fill={hex} opacity="0.16" filter="url(#map-blur)" />
                    ) : null}
                    <circle cx={point.x} cy={point.y} r={radius} fill={`${hex}22`} stroke={hex} strokeWidth={active ? 2.4 : 1.3} />
                    {region.attacks > 0 ? <circle cx={point.x} cy={point.y} r={radius * 0.42} fill={hex} opacity="0.85" /> : null}
                    <text x={point.x} y={point.y - radius - 6} textAnchor="middle" className="fill-slate-300" style={{ fontSize: 10, fontWeight: 600 }}>
                      {region.region}
                    </text>
                    <text x={point.x} y={point.y + radius + 12} textAnchor="middle" className="fill-slate-500" style={{ fontSize: 9, fontFamily: 'monospace' }}>
                      {formatNumber(region.flows)} flows · {formatNumber(region.attacks)} atk
                    </text>
                  </g>
                )
              })}
            </svg>

            <div className="flex flex-wrap items-center gap-3 px-2 py-2">
              <Switch checked={showBenign} onChange={setShowBenign} label="Show benign links" hint="Off = attack flows only" />
              <div className="ml-auto flex flex-wrap items-center gap-2">
                {Object.entries(
                  links.reduce((acc, link) => {
                    if (!link.is_attack) return acc
                    acc[link.attack_type] = (acc[link.attack_type] || 0) + 1
                    return acc
                  }, {}),
                )
                  .sort((a, b) => b[1] - a[1])
                  .slice(0, 5)
                  .map(([name, count]) => (
                    <span key={name} className="badge border-slate-700/70 bg-slate-800/50" style={{ color: attackColor(name) }}>
                      <span className="h-1.5 w-1.5 rounded-full" style={{ background: attackColor(name) }} />
                      {name} · {count}
                    </span>
                  ))}
              </div>
            </div>
          </div>

          <p className="muted mt-2 flex items-start gap-1.5">
            <Info size={11} className="mt-0.5 shrink-0" />
            {data?.privacy || 'IP addresses are abstracted to /16 prefixes and mapped to synthetic regions.'} Snapshot generated{' '}
            {data?.generated_at ? timeAgo(data.generated_at) : '—'}.
          </p>

          {hoverLink ? (
            <div className="mt-2 rounded-lg border border-slate-800 bg-slate-950/50 px-3 py-2">
              <div className="flex flex-wrap items-center gap-2">
                <span className="mono text-[11px] text-slate-200">
                  {hoverLink.source} <ArrowRight size={10} className="inline text-slate-500" /> {hoverLink.target}
                </span>
                <AttackBadge type={hoverLink.attack_type} />
                <Badge tone={hoverLink.is_attack ? 'red' : 'slate'}>{hoverLink.is_attack ? 'attack flow' : 'benign flow'}</Badge>
              </div>
              <p className="muted mt-1">
                {formatNumber(hoverLink.flows)} flows · {compactNumber(hoverLink.packets)} packets · mean risk{' '}
                {formatPercent(hoverLink.risk, 1)} · source region {hoverLink.source_region}
              </p>
            </div>
          ) : null}
        </Card>

        <div className="space-y-4">
          <Card title="Region leaderboard" subtitle="Attack concentration by abstracted region" icon={Globe2} bodyClass="p-0">
            {regionStats.length === 0 ? (
              <EmptyState title="No regional data" message="No flows were recorded in this window." />
            ) : (
              <ul className="max-h-[280px] divide-y divide-slate-800/60 overflow-y-auto">
                {regionStats.map((region) => (
                  <li key={region.region} className="px-3.5 py-2">
                    <div className="flex items-center justify-between gap-2">
                      <span className="truncate text-[11.5px] font-medium text-slate-200">{region.region}</span>
                      <span className="mono shrink-0 text-[10.5px] text-slate-400">{formatNumber(region.attacks)} atk</span>
                    </div>
                    <Progress
                      className="mt-1.5"
                      value={Number(region.risk || 0) * 100}
                      max={100}
                      tone={Number(region.risk) >= 0.5 ? 'red' : Number(region.risk) >= 0.28 ? 'amber' : 'cyan'}
                    />
                    <p className="muted mt-1">
                      {formatNumber(region.flows)} flows · {compactNumber(region.packets)} packets · mean risk {formatPercent(region.risk, 1)}
                    </p>
                  </li>
                ))}
              </ul>
            )}
          </Card>

          {selectedRegion ? (
            <Card title={`${selectedRegion} endpoints`} subtitle="Nodes mapped to this region" icon={Server} bodyClass="p-0" dense>
              <ul className="max-h-56 divide-y divide-slate-800/60 overflow-y-auto">
                {nodes
                  .filter((node) => node.region === selectedRegion)
                  .map((node) => (
                    <li key={node.id} className="px-3.5 py-2">
                      <div className="flex items-center justify-between gap-2">
                        <span className="mono truncate text-[11px] text-slate-200">{user?.role === 'viewer' ? node.masked : node.ip}</span>
                        <Badge tone={node.role === 'target' ? 'amber' : 'cyan'}>{node.role}</Badge>
                      </div>
                      <p className="muted mt-0.5">
                        {formatNumber(node.flows)} flows · {formatNumber(node.attacks)} attacks · {compactNumber(node.packets)} pkts · risk{' '}
                        {formatPercent(node.risk, 1)}
                      </p>
                    </li>
                  ))}
                {nodes.filter((node) => node.region === selectedRegion).length === 0 ? (
                  <li className="muted px-3.5 py-3">No endpoints mapped to this region in the current window.</li>
                ) : null}
              </ul>
            </Card>
          ) : null}
        </div>
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <Card title="Attack links" subtitle="Source → destination pairs with attack verdicts" icon={ShieldAlert} bodyClass="p-0">
          <DataTable
            columns={[
              { key: 'source', header: 'Source', mono: true, render: (row) => <span className="mono">{row.source}</span> },
              { key: 'target', header: 'Target', mono: true, render: (row) => <span className="mono">{row.target}</span> },
              { key: 'attack_type', header: 'Verdict', width: '130px', render: (row) => <AttackBadge type={row.attack_type} /> },
              { key: 'flows', header: 'Flows', align: 'right', width: '70px', sortable: true, render: (row) => <span className="mono">{formatNumber(row.flows)}</span> },
              { key: 'packets', header: 'Packets', align: 'right', width: '90px', sortable: true, render: (row) => <span className="mono">{compactNumber(row.packets)}</span> },
              { key: 'risk', header: 'Risk', align: 'right', width: '86px', sortable: true, render: (row) => <span className="mono">{formatPercent(row.risk, 0)}</span> },
            ]}
            rows={(data?.links || []).filter((link) => link.is_attack)}
            rowKey={(row) => `${row.source}-${row.target}-${row.attack_type}`}
            maxHeight={320}
            empty={<EmptyState icon={ShieldAlert} title="No attack links" message="No attack verdicts were recorded between mapped endpoints in this window." />}
          />
        </Card>

        <Card title="Most targeted endpoints" subtitle="Destinations receiving attack verdicts" icon={Target} bodyClass="p-0">
          <DataTable
            columns={[
              { key: 'id', header: 'Endpoint', mono: true, render: (row) => <span className="mono">{user?.role === 'viewer' ? row.masked : row.id}</span> },
              { key: 'region', header: 'Region', width: '140px' },
              { key: 'role', header: 'Role', width: '84px', render: (row) => <Badge tone={row.role === 'target' ? 'amber' : 'cyan'}>{row.role}</Badge> },
              { key: 'flows', header: 'Flows', align: 'right', width: '74px', sortable: true, render: (row) => <span className="mono">{formatNumber(row.flows)}</span> },
              { key: 'attacks', header: 'Attacks', align: 'right', width: '80px', sortable: true, render: (row) => (row.attacks ? <Badge tone="red">{formatNumber(row.attacks)}</Badge> : '0') },
              { key: 'packets', header: 'Volume', align: 'right', width: '96px', sortable: true, render: (row) => <span className="mono">{formatBytes(row.packets * 128, 0)}</span> },
            ]}
            rows={[...nodes].sort((a, b) => Number(b.attacks) - Number(a.attacks)).slice(0, 25)}
            rowKey={(row) => `${row.id}-${row.role}`}
            maxHeight={320}
            empty={<EmptyState icon={Target} title="No endpoints mapped" message="Analyse traffic to populate the map." />}
          />
        </Card>
      </div>
    </div>
  )
}
