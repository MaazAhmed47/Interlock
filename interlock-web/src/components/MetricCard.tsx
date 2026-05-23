interface Props {
  label: string
  value: string | number
  sub?: string
  accent?: 'red' | 'cyan'
}

export default function MetricCard({ label, value, sub, accent }: Props) {
  const cls = accent ? `metric-card-value accent-${accent}` : 'metric-card-value'
  return (
    <div className="metric-card">
      <div className="metric-card-label">{label}</div>
      <div className={cls}>{value}</div>
      {sub && <div className="metric-card-sub">{sub}</div>}
    </div>
  )
}
