import { Link } from 'react-router-dom'
import { KeyRound } from 'lucide-react'

interface Props { message?: string; showSettingsLink?: boolean }

export default function EmptyState({ message = 'No API key configured.', showSettingsLink = true }: Props) {
  return (
    <div className="empty-state">
      <KeyRound size={28} />
      <p>{message}</p>
      {showSettingsLink && (
        <Link to="/dashboard/settings" className="btn btn-ghost btn-sm">Go to Settings →</Link>
      )}
    </div>
  )
}
