const API_BASE = '/api/dashboard'

export interface OverviewData {
  status: string
  uptime_seconds: number
  version: string
  routes_count: number
  upstreams_count: number
  circuit_breakers: {
    open: number
    half_open: number
    closed: number
  }
}

export interface RouteInfo {
  id: string
  name: string
  paths: string[]
  hosts?: string[]
  methods?: string[]
  upstream_id?: string
  enabled: boolean
  auth_required: boolean
  required_roles?: string[]
  required_scopes?: string[]
  rate_limit_key?: string
  strip_path: boolean
  path_rewrite?: string
  mirror_enabled: boolean
  priority: number
  headers?: Record<string, string>
}

export interface RoutesData {
  routes: RouteInfo[]
}

export interface TargetInfo {
  url: string
  weight: number
}

export interface UpstreamInfo {
  id: string
  name: string
  targets: TargetInfo[]
  circuit_breaker_state?: string
}

export interface UpstreamsData {
  upstreams: UpstreamInfo[]
}

export interface MetricsData {
  http: {
    requests_in_flight: number
  }
  rate_limiting: Record<string, unknown>
  circuit_breakers: Record<string, unknown>
  mirror: Record<string, unknown>
}

async function fetchJson<T>(url: string): Promise<T> {
  const response = await fetch(url)
  if (!response.ok) {
    throw new Error(`HTTP error! status: ${response.status}`)
  }
  return response.json()
}

export const dashboardApi = {
  getOverview: () => fetchJson<OverviewData>(API_BASE),
  getRoutes: () => fetchJson<RoutesData>(`${API_BASE}/routes`),
  getUpstreams: () => fetchJson<UpstreamsData>(`${API_BASE}/upstreams`),
  getMetrics: () => fetchJson<MetricsData>(`${API_BASE}/metrics`),
}
