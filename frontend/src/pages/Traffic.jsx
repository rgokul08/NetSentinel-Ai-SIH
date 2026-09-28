import React, { useState } from 'react'
import api from '../api.js'
import { Badge, ErrorBox, Loading, useFetch } from '../ui.jsx'

const ATTACKS = ['', 'DoS', 'DDoS', 'Port Scan', 'Brute Force', 'Botnet', 'Malware']

export default function Traffic() {
  const [tick, setTick] = useState(0)
  const [forced, setForced] = useState('')
  const { data, error } = useFetch(() => api.get('/traffic/live', { params: { limit: 30 } }), [tick], 5000)

  const simulate = async () => {
    await api.post('/traffic/simulate', null, { params: forced ? { forced_attack: forced } : {} })
    setTick((t) => t + 1)
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h1 className="text-2xl font-bold">Live Traffic</h1>
        <div className="flex gap-2">
          <select className="input w-40" value={forced} onChange={(e) => setForced(e.target.value)}>
            {ATTACKS.map((a) => <option key={a} value={a}>{a || 'Random packet'}</option>)}
          </select>
          <button className="btn" onClick={simulate}>Inject packet</button>
        </div>
      </div>
      {error && <ErrorBox msg={error} />}
      {!data ? <Loading /> : (
        <div className="card overflow-x-auto">
          <table className="w-full"><thead><tr>
            {['Time', 'Source', 'Destination', 'Port', 'Proto', 'PPS', 'Type', 'Risk'].map((h) => <th key={h} className="th">{h}</th>)}
          </tr></thead><tbody>
            {data.map((f) => (
              <tr key={f.id}>
                <td className="td">{new Date(f.timestamp).toLocaleTimeString()}</td>
                <td className="td font-mono">{f.source_ip}</td>
                <td className="td font-mono">{f.destination_ip}</td>
                <td className="td">{f.destination_port}</td>
                <td className="td">{f.protocol}</td>
                <td className="td">{f.packets_per_second}</td>
                <td className="td">{f.attack_type}</td>
                <td className="td"><Badge level={f.risk_level} /></td>
              </tr>
            ))}
          </tbody></table>
        </div>
      )}
    </div>
  )
}
