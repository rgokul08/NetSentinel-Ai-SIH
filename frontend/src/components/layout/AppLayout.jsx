import { useEffect, useState } from 'react'
import { Outlet, useLocation } from 'react-router-dom'
import Sidebar from './Sidebar'
import Topbar from './Topbar'
import { DATA_ORIGIN_LABELS } from '../../utils/constants'
import { useRealtime } from '../../context/RealtimeContext'
import { simulationApi } from '../../services/endpoints'

/** Simulation provenance banner: synthetic traffic is always disclosed. */
function SimulationBanner() {
  const { events } = useRealtime()
  const [state, setState] = useState(null)

  useEffect(() => {
    let cancelled = false
    const load = async () => {
      try {
        const status = await simulationApi.status()
        if (!cancelled) setState(status)
      } catch {
        if (!cancelled) setState(null)
      }
    }
    load()
    const timer = setInterval(load, 10000)
    return () => {
      cancelled = true
      clearInterval(timer)
    }
  }, [events.length])

  if (!state?.running && !state?.generated_flows) return null

  return (
    <div className="flex flex-wrap items-center gap-x-3 gap-y-1 border-b border-purple-500/25 bg-purple-500/8 px-4 py-1.5 text-[11px] text-purple-200">
      <span className="font-semibold uppercase tracking-wide">
        {state.running ? 'Simulation running' : 'Simulation data present'}
      </span>
      <span className="opacity-85">
        {state.generated_flows?.toLocaleString?.() || 0} synthetic flows generated · scenario {state.scenario || 'n/a'} ·{' '}
        {DATA_ORIGIN_LABELS[state.data_origin] || 'synthetic'}
      </span>
      <span className="opacity-70">Synthetic traffic is never presented as real network data.</span>
    </div>
  )
}

export default function AppLayout() {
  const [navOpen, setNavOpen] = useState(false)
  const location = useLocation()

  useEffect(() => {
    setNavOpen(false)
    window.scrollTo({ top: 0 })
  }, [location.pathname])

  return (
    <div className="min-h-screen">
      <Sidebar open={navOpen} onClose={() => setNavOpen(false)} />
      <div className="flex min-h-screen flex-col lg:pl-[248px]">
        <Topbar onMenu={() => setNavOpen(true)} />
        <SimulationBanner />
        <main className="flex-1 px-3 py-4 sm:px-5 sm:py-5">
          <div className="mx-auto w-full max-w-[1600px]">
            <Outlet />
          </div>
        </main>
        <footer className="border-t border-slate-800/70 px-4 py-3 text-center">
          <p className="muted">
            CyberForecast AI · AI-Based Network Attack Forecasting &amp; Blockchain-Assured Cybersecurity · Smart India Hackathon
            (Blockchain &amp; Cybersecurity theme)
          </p>
        </footer>
      </div>
    </div>
  )
}
