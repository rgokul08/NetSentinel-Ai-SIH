import React, { useState } from 'react'
import { Area, CartesianGrid, ComposedChart, Legend, Line, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import api from '../api.js'
import { Badge, ErrorBox, Loading, Stat, useFetch } from '../ui.jsx'

export default function Forecast() {
  const [hours, setHours] = useState(24)
  const { data, error } = useFetch(() => api.get('/forecast', { params: { hours } }), [hours])
  if (error) return <ErrorBox msg={error} />
  if (!data) return <Loading />
  const s = data.summary
  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Attack Forecast</h1>
        <select className="input w-32" value={hours} onChange={(e) => setHours(Number(e.target.value))}>
          {[12, 24, 48, 72].map((h) => <option key={h} value={h}>{h} hours</option>)}
        </select>
      </div>
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <Stat label="Overall probability" value={`${(s.overall_attack_probability * 100).toFixed(0)}%`} />
        <Stat label="Threat level" value={<Badge level={s.overall_threat_level} />} />
        <Stat label="Peak time" value={s.peak_threat_time} sub={s.peak_expected_attack} />
        <Stat label="Projected attacks" value={s.projected_attack_count_24h} sub={s.forecast_model} />
      </div>
      <div className="card h-96">
        <ResponsiveContainer width="100%" height="100%">
          <ComposedChart data={data.forecast_trend}>
            <CartesianGrid stroke="#1e293b" />
            <XAxis dataKey="time" stroke="#64748b" fontSize={11} />
            <YAxis stroke="#64748b" fontSize={11} />
            <Tooltip contentStyle={{ background: '#0f172a', border: '1px solid #334155' }} />
            <Legend />
            <Area dataKey="upper_bound" stroke="none" fill="#22d3ee22" name="Upper bound" />
            <Line dataKey="forecasted_attacks" stroke="#22d3ee" dot={false} name="Forecast" />
            <Line dataKey="lower_bound" stroke="#64748b" dot={false} strokeDasharray="4 4" name="Lower bound" />
          </ComposedChart>
        </ResponsiveContainer>
      </div>
    </div>
  )
}
