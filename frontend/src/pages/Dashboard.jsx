import React from 'react'
import { Area, AreaChart, CartesianGrid, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import api from '../api.js'
import { Badge, ErrorBox, Loading, Stat, useFetch } from '../ui.jsx'

const COLORS = ['#22d3ee', '#f43f5e', '#f59e0b', '#a855f7', '#10b981', '#3b82f6', '#ec4899', '#94a3b8']

export default function Dashboard() {
  const { data, error } = useFetch(() => api.get('/dashboard/overview'), [], 10000)
  if (error) return <ErrorBox msg={error} />
  if (!data) return <Loading />
  const { stats: s, recent_flows, recent_alerts, forecast_preview, attack_distribution } = data
  const dist = (attack_distribution || []).map((d) => ({ name: d.name || d.attack_type || d.type, value: d.value ?? d.count ?? d.percentage ?? 0 }))

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Security Overview</h1>
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <Stat label="Total flows" value={s.total_network_traffic} />
        <Stat label="Threat level" value={<Badge level={s.current_threat_level} />} sub={`P(attack) ${(s.attack_probability * 100).toFixed(0)}%`} />
        <Stat label="Attacks detected" value={s.detected_attacks_count} sub={`${s.suspicious_traffic_percentage}% of traffic`} />
        <Stat label="Health score" value={s.network_health_score} sub={`${s.active_alerts_count} active alerts`} />
      </div>
      <div className="grid lg:grid-cols-3 gap-4">
        <div className="card lg:col-span-2 h-72">
          <div className="text-sm text-slate-400 mb-2">Forecast preview (next hours)</div>
          <ResponsiveContainer width="100%" height="90%">
            <AreaChart data={forecast_preview}>
              <CartesianGrid stroke="#1e293b" />
              <XAxis dataKey="time" stroke="#64748b" fontSize={11} />
              <YAxis stroke="#64748b" fontSize={11} />
              <Tooltip contentStyle={{ background: '#0f172a', border: '1px solid #334155' }} />
              <Area dataKey="forecasted_attacks" stroke="#22d3ee" fill="#22d3ee33" />
            </AreaChart>
          </ResponsiveContainer>
        </div>
        <div className="card h-72">
          <div className="text-sm text-slate-400 mb-2">Attack distribution</div>
          <ResponsiveContainer width="100%" height="90%">
            <PieChart>
              <Pie data={dist} dataKey="value" nameKey="name" outerRadius={80}>
                {dist.map((_, i) => <Cell key={i} fill={COLORS[i % COLORS.length]} />)}
              </Pie>
              <Tooltip contentStyle={{ background: '#0f172a', border: '1px solid #334155' }} />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>
      <div className="grid lg:grid-cols-2 gap-4">
        <div className="card overflow-x-auto">
          <div className="text-sm text-slate-400 mb-2">Recent flows</div>
          <table className="w-full"><thead><tr><th className="th">Source</th><th className="th">Dest</th><th className="th">Type</th><th className="th">Risk</th></tr></thead>
            <tbody>{recent_flows.map((f) => (
              <tr key={f.id}><td className="td font-mono">{f.source_ip}</td><td className="td font-mono">{f.destination_ip}</td><td className="td">{f.attack_type}</td><td className="td"><Badge level={f.risk_level} /></td></tr>
            ))}</tbody></table>
        </div>
        <div className="card overflow-x-auto">
          <div className="text-sm text-slate-400 mb-2">Recent alerts</div>
          <table className="w-full"><thead><tr><th className="th">Code</th><th className="th">Type</th><th className="th">Severity</th><th className="th">Status</th></tr></thead>
            <tbody>{recent_alerts.map((a) => (
              <tr key={a.id}><td className="td font-mono">{a.alert_code}</td><td className="td">{a.attack_type}</td><td className="td"><Badge level={a.severity} /></td><td className="td">{a.status}</td></tr>
            ))}</tbody></table>
        </div>
      </div>
    </div>
  )
}
