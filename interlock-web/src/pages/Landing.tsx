import { useEffect } from 'react'

export default function Landing() {
  useEffect(() => {
    window.location.replace('/')
  }, [])

  return null
}
