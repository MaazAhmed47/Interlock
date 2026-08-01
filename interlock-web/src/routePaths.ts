export const PUBLIC_DASHBOARD_LANDING = '/dashboard/proof'
export const DASHBOARD_OVERVIEW_PATH = '/dashboard/overview'

export function normalizeRoutePath(pathname: string): string {
  const withoutTrailingSlashes = pathname.replace(/\/+$/, '')
  return withoutTrailingSlashes || '/'
}

export function isProofRoutePath(pathname: string): boolean {
  return normalizeRoutePath(pathname) === '/dashboard/proof'
}
