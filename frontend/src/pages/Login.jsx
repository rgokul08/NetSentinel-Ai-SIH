import React, { useState } from 'react'
import { ShieldCheck } from 'lucide-react'
import api from '../api.js'

export default function Login({ onLogin }) {
  const [email, setEmail] = useState('admin@soc.guard')
  const [password, setPassword] = useState('Admin@1234')
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)

  const submit = async (e) => {
    e.preventDefault(); setBusy(true); setErr('')
    try {
      const { data } = await api.post('/auth/login', { email, password })
      localStorage.setItem('token', data.access_token)
      localStorage.setItem('user', JSON.stringify(data.user))
      onLogin(data.user)
    } catch (ex) {
      const d = ex.response?.data?.detail
      setErr(typeof d === 'string' ? d : ex.response ? 'Login failed' : 'Cannot reach the backend on port 8000')
    } finally { setBusy(false) }
  }

  return (
    <div className="min-h-screen flex items-center justify-center p-4">
      <form onSubmit={submit} className="card w-full max-w-sm space-y-4">
        <div className="flex items-center gap-2 text-soc-cyan font-bold text-lg"><ShieldCheck /> NetSentinel AI</div>
        <p className="text-sm text-slate-400">AI network attack forecasting — SOC sign in</p>
        <input className="input" type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="Email" required />
        <input className="input" type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Password" required />
        {err && <div className="text-rose-400 text-sm">{err}</div>}
        <button className="btn w-full" disabled={busy}>{busy ? 'Signing in…' : 'Sign in'}</button>
      </form>
    </div>
  )
}
