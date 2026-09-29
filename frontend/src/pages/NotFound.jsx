import { Link } from 'react-router-dom'
import { Compass } from 'lucide-react'
import { Button } from '../components/ui'

export default function NotFound() {
  return (
    <div className="card mx-auto mt-10 max-w-lg p-10 text-center">
      <div className="mx-auto mb-4 w-fit rounded-full border border-slate-700 bg-slate-800/50 p-4">
        <Compass size={24} className="text-slate-400" />
      </div>
      <p className="mono text-[11px] uppercase tracking-[0.2em] text-slate-500">Error 404</p>
      <h1 className="mt-2 text-lg font-semibold text-slate-100">This workspace does not exist</h1>
      <p className="muted mx-auto mt-2 max-w-sm">
        The page you requested is not part of the CyberForecast console. Use the navigation to return to a live view.
      </p>
      <div className="mt-5 flex justify-center gap-2">
        <Link to="/">
          <Button variant="primary">Back to command center</Button>
        </Link>
        <Link to="/alerts">
          <Button variant="secondary">Open alerts</Button>
        </Link>
      </div>
    </div>
  )
}
