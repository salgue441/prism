import { useUpstreams } from '../hooks/useDashboard'
import UpstreamCard from '../components/UpstreamCard'

export default function Upstreams() {
  const { data, isLoading, error } = useUpstreams()

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
        <p className="text-red-400">Failed to load upstreams</p>
        <p className="text-sm text-red-500 mt-1">{(error as Error).message}</p>
      </div>
    )
  }

  if (!data) return null

  const totalTargets = data.upstreams.reduce((sum, u) => sum + u.targets.length, 0)

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-white">Upstreams</h1>
        <div className="flex items-center gap-4 text-sm text-slate-400">
          <span>{data.upstreams.length} upstreams</span>
          <span>{totalTargets} targets</span>
        </div>
      </div>

      {data.upstreams.length === 0 ? (
        <div className="bg-slate-800 rounded-lg border border-slate-700 p-8 text-center">
          <p className="text-slate-500">No upstreams configured</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {data.upstreams.map((upstream) => (
            <UpstreamCard key={upstream.id} upstream={upstream} />
          ))}
        </div>
      )}
    </div>
  )
}
