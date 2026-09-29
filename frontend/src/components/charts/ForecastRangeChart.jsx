import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import ChartTooltip from './ChartTooltip'
import { EmptyState } from '../ui/states'
import { GRID_COLOR } from '../../utils/theme'
import { attackColor } from '../../utils/theme'
import { formatPercent } from '../../utils/format'

/**
 * Per-category forecast probability with the model's 95% interval drawn as a
 * floating range bar, so estimates are never presented as certainties.
 */
export default function ForecastRangeChart({ data = [], height = 260, valueKey = 'probability' }) {
  if (!data.length) {
    return (
      <div style={{ height }} className="flex items-center justify-center">
        <EmptyState title="No forecast categories" message="Run a forecast to see per-category probabilities." className="py-4" />
      </div>
    )
  }

  const rows = data.map((item) => {
    const probability = Number(item[valueKey] ?? item.probability ?? 0)
    const lower = Number(item.lower_bound ?? 0)
    const upper = Number(item.upper_bound ?? 0)
    return {
      ...item,
      probability,
      base: lower,
      range: Math.max(0, upper - lower),
      color: attackColor(item.attack_type || item.name),
    }
  })

  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart data={rows} layout="vertical" margin={{ top: 4, right: 26, bottom: 0, left: 6 }} barGap={-14}>
        <CartesianGrid stroke={GRID_COLOR} horizontal={false} />
        <XAxis
          type="number"
          domain={[0, (dataMax) => Math.max(1, Math.ceil(dataMax * 1.15))]}
          tickFormatter={(value) => `${value}`}
          stroke="#334155"
          tick={{ fontSize: 10, fill: '#64748b' }}
          tickLine={false}
          axisLine={{ stroke: '#1e293b' }}
        />
        <YAxis
          type="category"
          dataKey="attack_type"
          width={104}
          stroke="#334155"
          tick={{ fontSize: 10, fill: '#94a3b8' }}
          tickLine={false}
          axisLine={{ stroke: '#1e293b' }}
          interval={0}
        />
        <Tooltip
          cursor={{ fill: 'rgba(148,163,184,0.06)' }}
          content={
            <ChartTooltip
              valueFormatter={(value, entry) =>
                entry?.dataKey === 'range'
                  ? `${entry.payload.lower_bound} – ${entry.payload.upper_bound} expected events`
                  : formatPercent(value, 1)
              }
            />
          }
        />
        {/* invisible base lifts the range bar to the lower confidence bound */}
        <Bar dataKey="base" stackId="ci" fill="transparent" isAnimationActive={false} barSize={9} />
        <Bar dataKey="range" stackId="ci" name="95% interval" isAnimationActive={false} barSize={9} radius={[0, 3, 3, 0]}>
          {rows.map((row, index) => (
            <Cell key={index} fill={row.color} fillOpacity={0.28} />
          ))}
        </Bar>
        <Bar dataKey={valueKey} name="Probability" isAnimationActive={false} barSize={9} radius={[0, 3, 3, 0]}>
          {rows.map((row, index) => (
            <Cell key={index} fill={row.color} fillOpacity={0.92} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  )
}
