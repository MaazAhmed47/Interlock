import { useRef } from 'react'
import { motion, useInView } from 'framer-motion'
import { Link } from 'react-router-dom'
import { ArrowRight } from 'lucide-react'

export default function BuyerProof() {
  const ref = useRef<HTMLElement>(null)
  const inView = useInView(ref, { once: true, margin: '-80px' })

  return (
    <section ref={ref} id="proof" className="py-24 px-8 border-t border-[#27302B]">
      <div className="max-w-[1100px] mx-auto text-center">
        <motion.div
          initial={{ opacity: 0, y: 24 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          transition={{ duration: 0.5 }}
        >
          <p className="text-[#6B7670] text-xs font-mono tracking-widest uppercase mb-6">Why Security Teams Choose Interlock</p>
          <blockquote className="text-[#F4F7F5] font-bold max-w-2xl mx-auto leading-tight mb-8"
            style={{ fontSize: 'clamp(24px, 3.5vw, 40px)' }}>
            "Know what every agent was allowed to do<br className="hidden md:block" /> before it does it."
          </blockquote>

          <div className="flex flex-wrap justify-center gap-8 mb-12">
            {[
              { stat: '< 1ms', label: 'Policy evaluation overhead' },
              { stat: '100%', label: 'Tool decisions audited' },
              { stat: 'Zero', label: 'Trust assumed by default' },
            ].map(({ stat, label }) => (
              <div key={label} className="text-center">
                <p className="text-[#10B981] font-bold text-2xl mb-1">{stat}</p>
                <p className="text-[#6B7670] text-xs font-mono">{label}</p>
              </div>
            ))}
          </div>

          <Link
            to="/dashboard/drift"
            className="inline-flex items-center gap-2 bg-[#10B981] hover:bg-[#059669] text-[#080A09] font-semibold text-sm px-6 py-3 rounded transition-colors"
          >
            Launch Security Console <ArrowRight size={15} />
          </Link>
        </motion.div>
      </div>
    </section>
  )
}
