import { TOOLTIP_STYLE } from '../../utils/theme'

/** Shared tooltip so every chart in the platform looks identical. */
export default function ChartTooltip({ active, payload, label, labelFormatter, valueFormatter, unit = '' }) {
  if (!active || !payload?.length) return null
  return (
    <div style={TOOLTIP_STYLE.contentStyle} className="min-w-[150px] px-2.5 py-2">
      <p style={TOOLTIP_STYLE.labelStyle} className="mb-1.5">
        {labelFormatter ? labelFormatter(label) : label}
      </p>
      <ul className="space-y-1">
        {payload.map((entry, index) => (
          <li key={`${entry.name}-${index}`} className="flex items-center justify-between gap-4 text-[11px]">
            <span className="flex min-w-0 items-center gap-1.5 text-slate-400">
              <span className="h-2 w-2 shrink-0 rounded-sm" style={{ background: entry.color || entry.fill || entry.stroke }} />
              <span className="truncate">{entry.name}</span>
            </span>
            <span className="shrink-0 font-mono text-slate-100">
              {valueFormatter ? valueFormatter(entry.value, entry) : entry.value}
              {unit}
            </span>
          </li>
        ))}
      </ul>
    </div>
  )
}
