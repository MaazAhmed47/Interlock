import type { ReactNode } from 'react'

interface BadgeProps {
  children: ReactNode
  variant?: 'default' | 'success' | 'warning' | 'danger'
  className?: string
}

export default function Badge({ children, variant = 'default', className = '' }: BadgeProps) {
  const base = 'inline-flex items-center px-2 py-0.5 rounded text-xs font-medium'
  const variants = {
    default: 'bg-[var(--s3)] text-[var(--tx)]',
    success: 'bg-[var(--acs)] text-[var(--ac)]',
    warning: 'bg-[rgba(245,158,11,0.12)] text-[var(--or)]',
    danger:  'bg-[var(--rds)] text-[var(--rd)]',
  }
  return (
    <span className={`${base} ${variants[variant]} ${className}`}>
      {children}
    </span>
  )
}
