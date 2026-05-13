interface CodeBlockProps {
  code: string
  language?: string
  className?: string
}

export default function CodeBlock({ code, language = 'bash', className = '' }: CodeBlockProps) {
  return (
    <pre className={`bg-[var(--s1)] border border-[var(--bd)] rounded-lg p-4 overflow-x-auto text-sm font-mono text-[var(--tx)] ${className}`} data-language={language}>
      <code>{code}</code>
    </pre>
  )
}
