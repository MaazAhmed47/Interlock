import { AlertCircle, RefreshCw } from 'lucide-react'

interface Props { message: string; onRetry?: () => void }

export default function ErrorCard({ message, onRetry }: Props) {
  return (
    <div className="error-card">
      <AlertCircle size={15} style={{ color: 'var(--red)', flexShrink: 0 }} />
      <span style={{ flex: 1 }}>{message}</span>
      {onRetry && (
        <button className="btn btn-ghost btn-sm" onClick={onRetry}>
          <RefreshCw size={12} /> Retry
        </button>
      )}
    </div>
  )
}
