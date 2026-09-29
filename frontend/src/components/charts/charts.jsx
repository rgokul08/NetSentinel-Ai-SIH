import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Line,
  LineChart,
  Pie,
  PieChart,
  PolarAngleAxis,
  PolarGrid,
  PolarRadiusAxis,
  Radar,
  RadarChart,
  RadialBar,
  RadialBarChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import ChartTooltip from './ChartTooltip'
import { EmptyState } from '../ui/states'
import { CHART_PALETTE, GRID_COLOR, TOOLTIP_STYLE } from '../../utils/theme'
import { compactNumber, formatAxisTime, formatPercent } from '../../utils/format'

const axisProps = {
  stroke: '#334155',
  tick: { fontSize: 10, fill: '#64748b' },
  tickLine: false,
  axisLine: { stroke: '#1e293b' },
}

function NoData({ height, message }) {
  return (
    <div style={{ height }} className="flex items-center justify-center">
      <EmptyState title="No data to plot" message={message || 'Nothing has been recorded in this window yet.'} className="py-4" />
    </div>
  )
}

/** Multi-series time chart (area or line) used for traffic and attack trends. */
export function TimeSeriesChart({
  data,
  xKey = 'time',
  series = [],
  height = 240,
  stacked = false,
  type = 'area',
  xFormatter = formatAxisTime,
  yFormatter = compactNumber,
  emptyMessage,
}) {
  if (!data?.length || !series.length) return <NoData height={height} message={emptyMessage} />
  return (
    <ResponsiveContainer width="100%" height={height}>
      {type === 'line' ? (
        <LineChart data={data} margin={{ top: 6, right: 8, bottom: 0, left: -18 }}>
          <CartesianGrid stroke={GRID_COLOR} vertical={false} />
          <XAxis dataKey={xKey} tickFormatter={xFormatter} {...axisProps} minTickGap={28} />
          <YAxis tickFormatter={yFormatter} {...axisProps} width={52} />
          <Tooltip content={<ChartTooltip labelFormatter={xFormatter} valueFormatter={(value) => yFormatter(value)} />} />
          {series.length > 1 ? <Legend wrapperStyle={{ fontSize: 10, color: '#94a3b8' }} iconSize={8} /> : null}
          {series.map((item) => (
            <Line
              key={item.key}
              type="monotone"
              dataKey={item.key}
              name={item.label}
              stroke={item.color}
              strokeWidth={item.width || 1.8}
              dot={false}
              strokeDasharray={item.dashed ? '4 3' : undefined}
              isAnimationActive={false}
            />
          ))}
        </LineChart>
      ) : (
        <AreaChart data={data} margin={{ top: 6, right: 8, bottom: 0, left: -18 }}>
          <defs>
            {series.map((item) => (
              <linearGradient key={item.key} id={`grad-${item.key}`} x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={item.color} stopOpacity={item.opacity ?? 0.42} />
                <stop offset="100%" stopColor={item.color} stopOpacity={0.02} />
              </linearGradient>
            ))}
          </defs>
          <CartesianGrid stroke={GRID_COLOR} vertical={false} />
          <XAxis dataKey={xKey} tickFormatter={xFormatter} {...axisProps} minTickGap={28} />
          <YAxis tickFormatter={yFormatter} {...axisProps} width={52} />
          <Tooltip content={<ChartTooltip labelFormatter={xFormatter} valueFormatter={(value) => yFormatter(value)} />} />
          {series.length > 1 ? <Legend wrapperStyle={{ fontSize: 10, color: '#94a3b8' }} iconSize={8} /> : null}
          {series.map((item) => (
            <Area
              key={item.key}
              type="monotone"
              dataKey={item.key}
              name={item.label}
              stroke={item.color}
              strokeWidth={item.width || 1.8}
              fill={`url(#grad-${item.key})`}
              stackId={stacked ? 'stack' : undefined}
              isAnimationActive={false}
            />
          ))}
        </AreaChart>
      )}
    </ResponsiveContainer>
  )
}

/** Categorical bar chart (attack distribution, top sources, protocol mix). */
export function CategoryBarChart({
  data,
  xKey = 'name',
  yKey = 'value',
  height = 240,
  horizontal = false,
  color,
  palette = CHART_PALETTE,
  colorBy = null,
  formatter = compactNumber,
  emptyMessage,
  showLabels = true,
}) {
  if (!data?.length) return <NoData height={height} message={emptyMessage} />
  const Axis = horizontal ? YAxis : XAxis
  const ValueAxis = horizontal ? XAxis : YAxis
  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart
        data={data}
        layout={horizontal ? 'vertical' : 'horizontal'}
        margin={{ top: 6, right: 12, bottom: 0, left: horizontal ? 8 : -18 }}
      >
        <CartesianGrid stroke={GRID_COLOR} horizontal={!horizontal} vertical={horizontal} />
        <Axis
          dataKey={xKey}
          type={horizontal ? 'category' : 'category'}
          {...axisProps}
          width={horizontal ? 108 : undefined}
          interval={0}
          angle={horizontal ? 0 : data.length > 6 ? -18 : 0}
          textAnchor={horizontal ? 'end' : data.length > 6 ? 'end' : 'middle'}
          height={horizontal ? undefined : 46}
        />
        <ValueAxis type="number" tickFormatter={formatter} {...axisProps} width={horizontal ? 46 : 52} />
        <Tooltip
          cursor={{ fill: 'rgba(148,163,184,0.06)' }}
          content={<ChartTooltip valueFormatter={(value) => formatter(value)} />}
        />
        <Bar dataKey={yKey} name="Count" radius={horizontal ? [0, 4, 4, 0] : [4, 4, 0, 0]} isAnimationActive={false} maxBarSize={38}>
          {showLabels ? null : null}
          {data.map((entry, index) => (
            <Cell key={index} fill={colorBy ? colorBy(entry) : color || palette[index % palette.length]} fillOpacity={0.88} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  )
}

/** Donut used for class splits and integrity verification ratios. */
export function DonutChart({
  data,
  height = 220,
  nameKey = 'name',
  valueKey = 'value',
  palette = CHART_PALETTE,
  colorBy = null,
  centerLabel = '',
  centerValue = '',
  innerRadius = '58%',
  outerRadius = '82%',
  formatter = compactNumber,
  emptyMessage,
}) {
  if (!data?.length) return <NoData height={height} message={emptyMessage} />
  return (
    <div className="relative" style={{ height }}>
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Tooltip content={<ChartTooltip valueFormatter={(value) => formatter(value)} />} />
          <Legend
            verticalAlign="bottom"
            iconType="circle"
            iconSize={7}
            wrapperStyle={{ fontSize: 10, color: '#94a3b8', paddingTop: 6 }}
          />
          <Pie
            data={data}
            dataKey={valueKey}
            nameKey={nameKey}
            innerRadius={innerRadius}
            outerRadius={outerRadius}
            paddingAngle={2}
            stroke="#0b1220"
            strokeWidth={2}
            isAnimationActive={false}
          >
            {data.map((entry, index) => (
              <Cell key={index} fill={colorBy ? colorBy(entry) : palette[index % palette.length]} />
            ))}
          </Pie>
        </PieChart>
      </ResponsiveContainer>
      {centerValue !== '' ? (
        <div className="pointer-events-none absolute inset-x-0 top-[38%] -translate-y-1/2 text-center">
          <p className="text-lg font-bold leading-none text-slate-100">{centerValue}</p>
          {centerLabel ? <p className="mt-1 text-[9.5px] font-semibold uppercase tracking-[0.14em] text-slate-500">{centerLabel}</p> : null}
        </div>
      ) : null}
    </div>
  )
}

/** Feature-contribution radar for XAI panels. */
export function ContributionRadar({ data, height = 250, color = '#22d3ee', nameKey = 'label', valueKey = 'impact' }) {
  if (!data?.length) return <NoData height={height} message="No attribution available for this decision." />
  return (
    <ResponsiveContainer width="100%" height={height}>
      <RadarChart data={data} outerRadius="72%">
        <PolarGrid stroke="rgba(148,163,184,0.16)" />
        <PolarAngleAxis dataKey={nameKey} tick={{ fontSize: 9, fill: '#94a3b8' }} />
        <PolarRadiusAxis tick={{ fontSize: 8, fill: '#475569' }} axisLine={false} tickCount={4} />
        <Tooltip {...TOOLTIP_STYLE} content={<ChartTooltip valueFormatter={(value) => Number(value).toFixed(2)} />} />
        <Radar name="Contribution" dataKey={valueKey} stroke={color} fill={color} fillOpacity={0.32} isAnimationActive={false} />
      </RadarChart>
    </ResponsiveContainer>
  )
}

/** Radial probability gauge (0-1). */
export function ProbabilityGauge({ value = 0, label = 'Probability', height = 170, color = '#22d3ee' }) {
  const percent = Math.max(0, Math.min(1, Number(value) || 0))
  const data = [{ name: label, value: Number((percent * 100).toFixed(1)), fill: color }]
  return (
    <div className="relative" style={{ height }}>
      <ResponsiveContainer width="100%" height="100%">
        <RadialBarChart innerRadius="68%" outerRadius="96%" data={data} startAngle={220} endAngle={-40} barSize={13}>
          <PolarAngleAxis type="number" domain={[0, 100]} tick={false} axisLine={false} />
          <RadialBar background={{ fill: 'rgba(148,163,184,0.10)' }} dataKey="value" cornerRadius={8} isAnimationActive={false} />
        </RadialBarChart>
      </ResponsiveContainer>
      <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
        <p className="text-2xl font-bold leading-none" style={{ color }}>
          {percent.toFixed(1) === '0.0' ? '0' : (percent * 100).toFixed(0)}%
        </p>
        <p className="mt-1 text-[9.5px] font-semibold uppercase tracking-[0.14em] text-slate-500">{label}</p>
      </div>
    </div>
  )
}

/** Tiny inline trend line for KPI cards. */
export function Sparkline({ data = [], dataKey = 'value', color = '#22d3ee', height = 34 }) {
  if (data.length < 2) return <div style={{ height }} />
  return (
    <ResponsiveContainer width="100%" height={height}>
      <AreaChart data={data} margin={{ top: 2, right: 0, bottom: 0, left: 0 }}>
        <defs>
          <linearGradient id={`spark-${dataKey}-${color.replace('#', '')}`} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={color} stopOpacity={0.45} />
            <stop offset="100%" stopColor={color} stopOpacity={0} />
          </linearGradient>
        </defs>
        <Area
          type="monotone"
          dataKey={dataKey}
          stroke={color}
          strokeWidth={1.4}
          fill={`url(#spark-${dataKey}-${color.replace('#', '')})`}
          isAnimationActive={false}
        />
      </AreaChart>
    </ResponsiveContainer>
  )
}

/** Percentage-style formatter reused by probability charts. */
export const percentFormatter = (value) => formatPercent(value, 0)
