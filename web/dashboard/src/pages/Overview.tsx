import { useOverview } from '../hooks/useDashboard'
import MetricCard from '../components/MetricCard'

function formatUptime(seconds: number): string {
  const days = Math.floor(seconds / 86400)
  const hours = Math.floor((seconds % 86400) / 3600)
  const minutes = Math.floor((seconds % 3600) / 60)

  if (days > 0) return `${days}d ${hours}h ${minutes}m`
  if (hours > 0) return `${hours}h ${minutes}m`
  return `${minutes}m`
}

export default function Overview() {
  const { data, isLoading, error } = useOverview()

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-slate-400">Loading...</div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="bg-red-900/20 border border-red-700 rounded-lg p-4">
        <p className="text-red-400">Failed to load dashboard data</p>
        <p className="text-sm text-red-500 mt-1">{(error as Error).message}</p>
      </div>
    )
  }

  if (!data) return null

  const statusType = data.status === 'healthy' ? 'success' : data.status === 'degraded' ? 'warning' : 'error'

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold text-white">System Overview</h1>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <MetricCard
          title="Status"
          value={data.status.charAt(0).toUpperCase() + data.status.slice(1)}
          status={statusType}
        />
        <MetricCard
          title="Uptime"
          value={formatUptime(data.uptime_seconds)}
          subtitle={`Version ${data.version}`}
        />
        <MetricCard
          title="Routes"
          value={data.routes_count}
          subtitle="Configured routes"
        />
        <MetricCard
          title="Upstreams"
          value={data.upstreams_count}
          subtitle="Backend services"
        />
      </div>

      <div className="bg-slate-800 rounded-lg p-6 border border-slate-700">
        <h2 className="text-lg font-medium text-white mb-4">Circuit Breakers</h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="bg-slate-700/50 rounded-lg p-4 text-center">
            <p className="text-3xl font-bold text-green-400">{data.circuit_breakers.closed}</p>
            <p className="text-sm text-slate-400 mt-1">Closed</p>
          </div>
          <div className="bg-slate-700/50 rounded-lg p-4 text-center">
            <p className="text-3xl font-bold text-yellow-400">{data.circuit_breakers.half_open}</p>
            <p className="text-sm text-slate-400 mt-1">Half-Open</p>
          </div>
          <div className="bg-slate-700/50 rounded-lg p-4 text-center">
            <p className="text-3xl font-bold text-red-400">{data.circuit_breakers.open}</p>
            <p className="text-sm text-slate-400 mt-1">Open</p>
          </div>
        </div>
      </div>
    </div>
  )
}
