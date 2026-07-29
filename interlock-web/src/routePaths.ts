export function normalizeRoutePath(pathname: string): string {
  const withoutTrailingSlashes = pathname.replace(/\/+$/, '')
  return withoutTrailingSlashes || '/'
}

export function isProofRoutePath(pathname: string): boolean {
  return normalizeRoutePath(pathname) === '/dashboard/proof'
}
