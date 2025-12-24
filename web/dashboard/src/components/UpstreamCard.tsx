import type { UpstreamInfo } from '../api/dashboard'

interface UpstreamCardProps {
  upstream: UpstreamInfo
}

const cbStateColors: Record<string, { bg: string; text: string }> = {
  closed: { bg: 'bg-green-900/50', text: 'text-green-300' },
  open: { bg: 'bg-red-900/50', text: 'text-red-300' },
  'half-open': { bg: 'bg-yellow-900/50', text: 'text-yellow-300' },
}

export default function UpstreamCard({ upstream }: UpstreamCardProps) {
  const cbColors = upstream.circuit_breaker_state
    ? cbStateColors[upstream.circuit_breaker_state.toLowerCase()] || cbStateColors['closed']
    : cbStateColors['closed']

  return (
    <div className="bg-slate-800 rounded-lg p-6 border border-slate-700">
      <div className="flex items-start justify-between">
        <div>
          <h3 className="text-lg font-medium text-white">{upstream.name || upstream.id}</h3>
          <p className="text-sm text-slate-500">{upstream.id}</p>
        </div>
        {upstream.circuit_breaker_state && (
          <span
            className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${cbColors.bg} ${cbColors.text}`}
          >
            CB: {upstream.circuit_breaker_state}
          </span>
        )}
      </div>
      <div className="mt-4">
        <h4 className="text-sm font-medium text-slate-400 mb-2">Targets</h4>
        <div className="space-y-2">
          {upstream.targets.map((target) => (
            <div
              key={target.url}
              className="flex items-center justify-between bg-slate-700/50 rounded px-3 py-2"
            >
              <span className="text-sm text-slate-300 font-mono">{target.url}</span>
              <span className="text-xs text-slate-500">weight: {target.weight}</span>
            </div>
          ))}
        </div>
        {upstream.targets.length === 0 && (
          <p className="text-sm text-slate-500">No targets configured</p>
        )}
      </div>
    </div>
  )
}
