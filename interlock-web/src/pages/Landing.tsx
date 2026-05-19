import Nav from '@/components/landing/Nav'
import Hero from '@/components/landing/Hero'
import Problem from '@/components/landing/Problem'
import HowItWorks from '@/components/landing/HowItWorks'
import Features from '@/components/landing/Features'
import WorkflowExample from '@/components/landing/WorkflowExample'
import BuyerProof from '@/components/landing/Stats'
import Footer from '@/components/landing/Footer'

export default function Landing() {
  return (
    <main className="bg-[#080A09] min-h-screen">
      <Nav />
      <Hero />
      <Problem />
      <HowItWorks />
      <Features />
      <WorkflowExample />
      <BuyerProof />
      <Footer />
    </main>
  )
}
