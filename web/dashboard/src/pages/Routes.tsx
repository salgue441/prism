import { useRoutes } from '../hooks/useDashboard'
import RouteTable from '../components/RouteTable'

export default function RoutesPage() {
  const { data, isLoading, error } = useRoutes()

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
        <p className="text-red-400">Failed to load routes</p>
        <p className="text-sm text-red-500 mt-1">{(error as Error).message}</p>
      </div>
    )
  }

  if (!data) return null

  const enabledCount = data.routes.filter((r) => r.enabled).length
  const authCount = data.routes.filter((r) => r.auth_required).length
  const mirrorCount = data.routes.filter((r) => r.mirror_enabled).length

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-white">Routes</h1>
        <div className="flex items-center gap-4 text-sm text-slate-400">
          <span>{data.routes.length} total</span>
          <span className="text-green-400">{enabledCount} enabled</span>
          <span className="text-purple-400">{authCount} with auth</span>
          <span className="text-cyan-400">{mirrorCount} mirrored</span>
        </div>
      </div>

      <div className="bg-slate-800 rounded-lg border border-slate-700 overflow-hidden">
        <RouteTable routes={data.routes} />
      </div>
    </div>
  )
}
