import React, { useState } from 'react'
import { NavLink, Navigate, Route, Routes } from 'react-router-dom'
import { Activity, AlertTriangle, BarChart3, FileText, LogOut, Radar, ShieldCheck, TrendingUp } from 'lucide-react'
import Login from './pages/Login.jsx'
import Dashboard from './pages/Dashboard.jsx'
import Traffic from './pages/Traffic.jsx'
import Detection from './pages/Detection.jsx'
import Forecast from './pages/Forecast.jsx'
import Alerts from './pages/Alerts.jsx'
import Reports from './pages/Reports.jsx'

const NAV = [
  ['/', 'Dashboard', BarChart3],
  ['/traffic', 'Live Traffic', Activity],
  ['/detection', 'Detection', Radar],
  ['/forecast', 'Forecast', TrendingUp],
  ['/alerts', 'Alerts', AlertTriangle],
  ['/reports', 'Reports & Model', FileText],
]

export default function App() {
  const [user, setUser] = useState(() => {
    try { return JSON.parse(localStorage.getItem('user')) } catch { return null }
  })

  const logout = () => {
    localStorage.removeItem('token'); localStorage.removeItem('user'); setUser(null)
  }

  if (!user) return <Login onLogin={setUser} />

  return (
    <div className="flex min-h-screen">
      <aside className="w-56 shrink-0 bg-soc-card border-r border-soc-border p-4 flex flex-col">
        <div className="flex items-center gap-2 font-bold text-soc-cyan mb-6">
          <ShieldCheck size={22} /> NetSentinel AI
        </div>
        <nav className="space-y-1 flex-1">
          {NAV.map(([to, label, Icon]) => (
            <NavLink key={to} to={to} end={to === '/'}
              className={({ isActive }) => `flex items-center gap-2 px-3 py-2 rounded-lg text-sm ${isActive ? 'bg-soc-accent/15 text-soc-cyan' : 'text-slate-300 hover:bg-soc-cardLight'}`}>
              <Icon size={16} /> {label}
            </NavLink>
          ))}
        </nav>
        <div className="text-xs text-slate-400 mb-2">{user.full_name}<br />{user.role}</div>
        <button onClick={logout} className="flex items-center gap-2 text-sm text-slate-300 hover:text-rose-400"><LogOut size={14} /> Sign out</button>
      </aside>
      <main className="flex-1 p-6 overflow-x-hidden">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/traffic" element={<Traffic />} />
          <Route path="/detection" element={<Detection />} />
          <Route path="/forecast" element={<Forecast />} />
          <Route path="/alerts" element={<Alerts />} />
          <Route path="/reports" element={<Reports />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>
    </div>
  )
}
