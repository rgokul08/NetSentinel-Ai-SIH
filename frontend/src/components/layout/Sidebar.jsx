import { Lock, ShieldHalf, X, Zap } from 'lucide-react'
import { NavLink } from 'react-router-dom'
import { NAV_GROUPS } from './nav'
import { useAuth } from '../../context/AuthContext'

export default function Sidebar({ open, onClose }) {
  const { can, user } = useAuth()

  const groups = NAV_GROUPS.map((group) => ({
    ...group,
    items: group.items.filter((item) => !item.capability || can(item.capability)),
  })).filter((group) => group.items.length > 0)

  return (
    <>
      {open ? (
        <div className="fixed inset-0 z-40 bg-slate-950/70 backdrop-blur-sm lg:hidden" onClick={onClose} role="presentation" aria-hidden="true" />
      ) : null}
      <aside
        className={`fixed inset-y-0 left-0 z-50 flex w-[248px] flex-col border-r border-slate-800/80 bg-[#080c14]/95 backdrop-blur transition-transform duration-200 lg:translate-x-0 ${
          open ? 'translate-x-0' : '-translate-x-full'
        }`}
      >
        <div className="flex items-center gap-2.5 border-b border-slate-800/80 px-4 py-3.5">
          <div className="relative flex h-9 w-9 items-center justify-center rounded-lg border border-cyan-500/40 bg-cyan-500/10">
            <ShieldHalf size={17} className="text-cyan-300" />
            <span className="absolute -right-0.5 -top-0.5 h-2 w-2 rounded-full bg-emerald-400 shadow-[0_0_8px_2px_rgba(52,211,153,0.6)]" />
          </div>
          <div className="min-w-0 flex-1">
            <p className="truncate text-[13px] font-bold tracking-tight text-slate-100">
              CyberForecast <span className="text-cyan-400">AI</span>
            </p>
            <p className="mono truncate text-[9.5px] uppercase tracking-[0.16em] text-slate-500">Attack forecasting SOC</p>
          </div>
          <button type="button" className="rounded p-1 text-slate-500 hover:text-slate-200 lg:hidden" onClick={onClose} aria-label="Close navigation">
            <X size={15} />
          </button>
        </div>

        <nav className="flex-1 overflow-y-auto px-2 pb-4">
          {groups.map((group) => (
            <div key={group.label}>
              <p className="nav-group">{group.label}</p>
              <div className="space-y-0.5">
                {group.items.map((item) => (
                  <NavLink
                    key={item.to}
                    to={item.to}
                    end={item.end}
                    onClick={onClose}
                    className={({ isActive }) => `nav-link ${isActive ? 'nav-link-active' : ''}`}
                    title={item.label}
                  >
                    <item.icon size={15} className="shrink-0" />
                    <span className="truncate">{item.label}</span>
                  </NavLink>
                ))}
              </div>
            </div>
          ))}
        </nav>

        <div className="border-t border-slate-800/80 px-3 py-3">
          <div className="rounded-lg border border-slate-800 bg-slate-900/60 px-2.5 py-2">
            <p className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wider text-slate-400">
              <Lock size={10} className="text-emerald-400" />
              Signed in as
            </p>
            <p className="mt-1 truncate text-xs font-medium text-slate-200">{user?.name || user?.email}</p>
            <p className="mono mt-0.5 flex items-center gap-1 text-[10px] uppercase tracking-wide text-cyan-400/90">
              <Zap size={9} /> {user?.role}
            </p>
          </div>
        </div>
      </aside>
    </>
  )
}
