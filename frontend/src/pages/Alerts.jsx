import React, { useState } from 'react'
import api from '../api.js'
import { Badge, ErrorBox, Loading, useFetch } from '../ui.jsx'

export default function Alerts() {
  const [sev, setSev] = useState('ALL')
  const [tick, setTick] = useState(0)
  const { data, error } = useFetch(() => api.get('/alerts', { params: { severity: sev } }), [sev, tick])

  const setStatus = async (id, status) => {
    const u = JSON.parse(localStorage.getItem('user') || '{}')
    await api.patch(`/alerts/${id}/status`, { status, resolved_by: status === 'Resolved' ? u.email : undefined })
    setTick((t) => t + 1)
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Alerts</h1>
        <select className="input w-36" value={sev} onChange={(e) => setSev(e.target.value)}>
          {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((s) => <option key={s}>{s}</option>)}
        </select>
      </div>
      {error && <ErrorBox msg={error} />}
      {!data ? <Loading /> : (
        <div className="card overflow-x-auto">
          <table className="w-full"><thead><tr>
            {['Code', 'Severity', 'Type', 'Source', 'Target', 'Status', 'Action'].map((h) => <th key={h} className="th">{h}</th>)}
          </tr></thead><tbody>
            {data.map((a) => (
              <tr key={a.id}>
                <td className="td font-mono">{a.alert_code}</td>
                <td className="td"><Badge level={a.severity} /></td>
                <td className="td">{a.attack_type}</td>
                <td className="td font-mono">{a.source_ip}</td>
                <td className="td font-mono">{a.destination_ip}</td>
                <td className="td">{a.status}</td>
                <td className="td">
                  <select className="input py-1" value={a.status} onChange={(e) => setStatus(a.id, e.target.value)}>
                    {['Open', 'Investigating', 'Resolved'].map((s) => <option key={s}>{s}</option>)}
                  </select>
                </td>
              </tr>
            ))}
          </tbody></table>
        </div>
      )}
    </div>
  )
}
