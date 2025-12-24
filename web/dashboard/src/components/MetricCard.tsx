interface MetricCardProps {
  title: string
  value: string | number
  subtitle?: string
  status?: 'success' | 'warning' | 'error' | 'neutral'
}

const statusColors = {
  success: 'text-green-400',
  warning: 'text-yellow-400',
  error: 'text-red-400',
  neutral: 'text-slate-300',
}

export default function MetricCard({ title, value, subtitle, status = 'neutral' }: MetricCardProps) {
  return (
    <div className="bg-slate-800 rounded-lg p-6 border border-slate-700">
      <h3 className="text-sm font-medium text-slate-400 uppercase tracking-wide">{title}</h3>
      <p className={`mt-2 text-3xl font-bold ${statusColors[status]}`}>{value}</p>
      {subtitle && <p className="mt-1 text-sm text-slate-500">{subtitle}</p>}
    </div>
  )
}
