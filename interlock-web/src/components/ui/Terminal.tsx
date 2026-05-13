import type { ReactNode } from 'react'

interface TerminalProps {
  lines?: string[]
  children?: ReactNode
  className?: string
}

export default function Terminal({ lines, children, className = '' }: TerminalProps) {
  return (
    <div
      className={className}
      style={{
        background: 'var(--s1)',
        border: '1px solid var(--bd)',
        borderRadius: 8,
        padding: '16px',
        fontFamily: 'JetBrains Mono, monospace',
        fontSize: 13,
      }}
    >
      {lines
        ? lines.map((line, i) => (
            <div key={i} style={{ color: 'var(--tx)', lineHeight: 1.6 }}>{line}</div>
          ))
        : children}
    </div>
  )
}
