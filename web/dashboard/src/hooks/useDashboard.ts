import { useQuery } from '@tanstack/react-query'
import { dashboardApi } from '../api/dashboard'

export function useOverview() {
  return useQuery({
    queryKey: ['overview'],
    queryFn: dashboardApi.getOverview,
  })
}

export function useRoutes() {
  return useQuery({
    queryKey: ['routes'],
    queryFn: dashboardApi.getRoutes,
  })
}

export function useUpstreams() {
  return useQuery({
    queryKey: ['upstreams'],
    queryFn: dashboardApi.getUpstreams,
  })
}

export function useMetrics() {
  return useQuery({
    queryKey: ['metrics'],
    queryFn: dashboardApi.getMetrics,
  })
}
