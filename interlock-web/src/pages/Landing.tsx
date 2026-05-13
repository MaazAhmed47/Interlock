import Nav from '../components/landing/Nav'
import Hero from '../components/landing/Hero'

export default function Landing() {
  return (
    <main style={{ background: 'var(--bg)', minHeight: '100vh' }}>
      <Nav />
      <Hero />
    </main>
  )
}
