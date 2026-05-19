import { type ButtonHTMLAttributes, forwardRef } from 'react'

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'ghost' | 'danger-ghost' | 'quarantine-ghost'
  size?: 'sm' | 'md'
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ variant = 'primary', size = 'md', className = '', children, ...props }, ref) => {
    const base = 'inline-flex items-center justify-center gap-1.5 rounded font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#10B981] disabled:opacity-50 disabled:pointer-events-none cursor-pointer'
    const sizes: Record<string, string> = { sm: 'px-3 py-1.5 text-xs', md: 'px-4 py-2 text-sm' }
    const variants: Record<string, string> = {
      primary:            'bg-[#10B981] text-[#080A09] hover:bg-[#059669] font-semibold',
      ghost:              'border border-[#27302B] text-[#9CA8A2] hover:border-[#10B981] hover:text-[#10B981] bg-transparent',
      'danger-ghost':     'border border-[#27302B] text-[#9CA8A2] hover:border-[#D86A4A] hover:text-[#D86A4A] bg-transparent',
      'quarantine-ghost': 'border border-[#27302B] text-[#9CA8A2] hover:border-[#A78BFA] hover:text-[#A78BFA] bg-transparent',
    }
    return (
      <button
        ref={ref}
        className={`${base} ${sizes[size]} ${variants[variant]} ${className}`}
        {...props}
      >
        {children}
      </button>
    )
  }
)
Button.displayName = 'Button'
