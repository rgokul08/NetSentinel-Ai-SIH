import { Activity, ArrowUpRight, Radio } from 'lucide-react'
import { Link } from 'react-router-dom'
import { EmptyState } from '../ui/states'
import { AttackBadge, Badge } from '../ui/primitives'
import { formatNumber, timeAgo } from '../../utils/format'
import { riskColor } from '../../utils/theme'

/** Streaming flow feed driven by persisted traffic records + websocket events. */
export default function LiveActivityFeed({ items = [], liveEvents = [], connected = false, max = 14, title = 'Live activity' }) {
  const merged = [
    ...liveEvents.slice(0, 6).map((event) => ({
      key: `ws-${event.timestamp || event.id || Math.random()}`,
      timestamp: event.timestamp || event.received_at,
      source_ip: event.source_ip,
      destination_ip: event.destination_ip,
      destination_port: event.destination_port,
      protocol: event.protocol,
      packet_count: event.packet_count,
      verdict: event.attack_type || event.verdict,
      risk_score: event.risk_score,
      risk_level: event.risk_level,
      live: true,
    })),
    ...items.map((item) => ({ ...item, key: item.record_id || item.id, live: false })),
  ].slice(0, max)

  return (
    <div className="card flex h-full flex-col">
      <header className="flex items-center justify-between gap-2 border-b border-slate-800/70 px-4 py-3">
        <h2 className="section-title flex items-center gap-2">
          <Activity size={14} className="text-cyan-400/80" /> {title}
        </h2>
        <span className={`badge ${connected ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-300' : 'border-slate-700 bg-slate-800/60 text-slate-400'}`}>
          <Radio size={9} className={connected ? 'animate-pulse' : ''} />
          {connected ? 'streaming' : 'polling'}
        </span>
      </header>

      {merged.length === 0 ? (
        <EmptyState
          icon={Activity}
          title="No flows yet"
          message="Start the simulation console or upload a dataset to populate the feed."
        />
      ) : (
        <ul className="divide-y divide-slate-800/60 overflow-y-auto">
          {merged.map((item) => {
            const isAttack = item.verdict && item.verdict !== 'Benign'
            const hex = riskColor(item.risk_level)
            return (
              <li key={item.key} className="flex items-center gap-2.5 px-4 py-2 transition hover:bg-slate-800/25">
                <span className="h-1.5 w-1.5 shrink-0 rounded-full" style={{ background: hex }} />
                <div className="min-w-0 flex-1">
                  <p className="mono flex items-center gap-1.5 truncate text-[11px] text-slate-200">
                    {item.live ? <span className="text-[9px] font-bold uppercase text-emerald-400">live</span> : null}
                    {item.source_ip || '?'} <ArrowUpRight size={9} className="shrink-0 text-slate-600" /> {item.destination_ip || '?'}
                    {item.destination_port ? <span className="text-slate-500">:{item.destination_port}</span> : null}
                  </p>
                  <p className="muted truncate">
                    {item.protocol || 'IP'} · {formatNumber(item.packet_count || 0)} pkts · {timeAgo(item.timestamp)}
                  </p>
                </div>
                <div className="flex shrink-0 items-center gap-1.5">
                  {item.verdict ? <AttackBadge type={item.verdict} /> : null}
                  <Badge tone={isAttack ? 'red' : 'slate'}>{((Number(item.risk_score) || 0) * 100).toFixed(0)}%</Badge>
                </div>
              </li>
            )
          })}
        </ul>
      )}

      <footer className="mt-auto border-t border-slate-800/70 px-4 py-2">
        <Link to="/traffic" className="muted transition hover:text-cyan-300">
          Open live traffic monitor →
        </Link>
      </footer>
    </div>
  )
}
