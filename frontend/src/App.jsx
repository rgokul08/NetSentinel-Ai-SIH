import { Suspense, lazy } from 'react'
import { Navigate, Route, Routes, useLocation } from 'react-router-dom'
import { ShieldAlert } from 'lucide-react'
import { AuthProvider, useAuth } from './context/AuthContext'
import { RealtimeProvider } from './context/RealtimeContext'
import { ToastProvider } from './context/ToastContext'
import AppLayout from './components/layout/AppLayout'
import { Button, LoadingState } from './components/ui'

/* Pages are code-split so the initial bundle stays small. */
const Login = lazy(() => import('./pages/Login'))
const ResetPassword = lazy(() => import('./pages/ResetPassword'))
const Dashboard = lazy(() => import('./pages/Dashboard'))
const Analytics = lazy(() => import('./pages/Analytics'))
const Timeline = lazy(() => import('./pages/Timeline'))
const ThreatMap = lazy(() => import('./pages/ThreatMap'))
const Traffic = lazy(() => import('./pages/Traffic'))
const Detection = lazy(() => import('./pages/Detection'))
const Forecast = lazy(() => import('./pages/Forecast'))
const Alerts = lazy(() => import('./pages/Alerts'))
const Reports = lazy(() => import('./pages/Reports'))
const Models = lazy(() => import('./pages/Models'))
const Datasets = lazy(() => import('./pages/Datasets'))
const Blockchain = lazy(() => import('./pages/Blockchain'))
const Simulation = lazy(() => import('./pages/Simulation'))
const AuditLog = lazy(() => import('./pages/AuditLog'))
const Admin = lazy(() => import('./pages/Admin'))
const Settings = lazy(() => import('./pages/Settings'))
const NotFound = lazy(() => import('./pages/NotFound'))

function PageFallback() {
  return <LoadingState label="Loading workspace…" className="py-24" />
}

/** Redirects unauthenticated visitors to /login, remembering where they came from. */
function RequireAuth({ children }) {
  const { isAuthenticated, initializing } = useAuth()
  const location = useLocation()

  if (initializing) return <LoadingState label="Restoring session…" className="py-24" />
  if (!isAuthenticated) return <Navigate to="/login" replace state={{ from: location.pathname }} />
  return children
}

/**
 * Capability gate. Rather than silently hiding a page (which looks broken), it
 * renders an explicit "not permitted" panel - the API enforces the same rule.
 */
function RequireCapability({ capability, title, children }) {
  const { can, role } = useAuth()
  if (!capability || can(capability)) return children
  return (
    <div className="card mx-auto max-w-lg p-8 text-center">
      <div className="mx-auto mb-3 w-fit rounded-full border border-amber-500/40 bg-amber-500/10 p-3">
        <ShieldAlert size={20} className="text-amber-300" />
      </div>
      <h2 className="text-sm font-semibold text-slate-100">{title || 'Insufficient permissions'}</h2>
      <p className="muted mx-auto mt-2 max-w-sm">
        Your role (<span className="font-mono text-amber-300">{role}</span>) does not include the{' '}
        <span className="font-mono text-slate-300">{capability}</span> capability, so this workspace is not available.
        The backend enforces the same rule on every request.
      </p>
      <div className="mt-4 flex justify-center">
        <Button variant="secondary" onClick={() => window.history.back()}>
          Go back
        </Button>
      </div>
    </div>
  )
}

function Workspace() {
  return (
    <RealtimeProvider>
      <Routes>
        <Route element={<AppLayout />}>
          <Route index element={<Dashboard />} />
          <Route path="analytics" element={<Analytics />} />
          <Route path="timeline" element={<Timeline />} />
          <Route path="threat-map" element={<ThreatMap />} />
          <Route path="traffic" element={<Traffic />} />
          <Route
            path="detection"
            element={
              <RequireCapability capability="predict.run" title="Detection Lab requires analyst access">
                <Detection />
              </RequireCapability>
            }
          />
          <Route path="forecast" element={<Forecast />} />
          <Route path="alerts" element={<Alerts />} />
          <Route path="reports" element={<Reports />} />
          <Route path="models" element={<Models />} />
          <Route path="datasets" element={<Datasets />} />
          <Route path="blockchain" element={<Blockchain />} />
          <Route path="simulation" element={<Simulation />} />
          <Route
            path="audit"
            element={
              <RequireCapability capability="audit.view" title="Audit logs are restricted to administrators">
                <AuditLog />
              </RequireCapability>
            }
          />
          <Route
            path="admin"
            element={
              <RequireCapability capability="users.manage" title="The admin console is restricted to administrators">
                <Admin />
              </RequireCapability>
            }
          />
          <Route path="settings" element={<Settings />} />
          <Route path="*" element={<NotFound />} />
        </Route>
      </Routes>
    </RealtimeProvider>
  )
}

export default function App() {
  return (
    <ToastProvider>
      <AuthProvider>
        <Suspense fallback={<PageFallback />}>
          <Routes>
            <Route path="/login" element={<Login />} />
            <Route path="/reset-password" element={<ResetPassword />} />
            <Route
              path="/*"
              element={
                <RequireAuth>
                  <Workspace />
                </RequireAuth>
              }
            />
          </Routes>
        </Suspense>
      </AuthProvider>
    </ToastProvider>
  )
}
