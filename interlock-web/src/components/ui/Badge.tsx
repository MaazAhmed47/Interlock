interface BadgeProps {
  label: string
  color?: 'emerald' | 'amber' | 'danger' | 'violet' | 'muted'
}

const colors: Record<string, string> = {
  emerald: 'bg-[rgba(16,185,129,0.12)]  text-[#10B981] border-[rgba(16,185,129,0.25)]',
  amber:   'bg-[rgba(214,162,58,0.12)]  text-[#D6A23A] border-[rgba(214,162,58,0.25)]',
  danger:  'bg-[rgba(216,106,74,0.12)]  text-[#D86A4A] border-[rgba(216,106,74,0.25)]',
  violet:  'bg-[rgba(167,139,250,0.12)] text-[#A78BFA] border-[rgba(167,139,250,0.25)]',
  muted:   'bg-[rgba(156,168,162,0.08)] text-[#6B7670] border-[rgba(156,168,162,0.15)]',
}

export function Badge({ label, color = 'muted' }: BadgeProps) {
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-mono font-medium border whitespace-nowrap ${colors[color]}`}>
      {label}
    </span>
  )
}
