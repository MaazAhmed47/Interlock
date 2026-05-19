interface EmptyStateProps { message: string; sub?: string }

export function EmptyState({ message, sub }: EmptyStateProps) {
  return (
    <div className="flex flex-col items-center justify-center py-20 text-center">
      <div className="w-10 h-10 rounded-full border border-[#27302B] flex items-center justify-center mb-4">
        <div className="w-4 h-4 rounded-full border-2 border-[#6B7670]" />
      </div>
      <p className="text-[#9CA8A2] text-sm font-medium">{message}</p>
      {sub && <p className="text-[#6B7670] text-xs mt-1">{sub}</p>}
    </div>
  )
}
