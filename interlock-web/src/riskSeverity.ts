/**
 * Risk-meter severity banding and availability.
 *
 * Single source of truth for what a risk meter shows: the numeric score, the
 * severity word, and the fill colour. Call sites take all three from one
 * `riskMeter()` result so they cannot drift apart — the meter used to fill solid
 * green at every score, which read as "healthy" at 59/100.
 *
 * Missing data is a distinct state, not a zero. A null/NaN score renders
 * "Risk unavailable" in neutral gray rather than "0/100 Low" with a green fill,
 * which would report an absent measurement as a reassuring one.
 *
 * Bands are inclusive integer ranges over 0-100:
 *   0-24 low - 25-49 moderate - 50-74 high - 75-100 critical
 */

/** Field labels. Threat severity and risk score are separate measurements that
 *  are reported independently; neither is derived from the other, and they are
 *  not expected to agree. */
export const THREAT_SEVERITY_LABEL = 'Threat severity'
export const RISK_SCORE_LABEL = 'Risk score'
export const RISK_UNAVAILABLE_LABEL = 'Risk unavailable'
export const RISK_UNAVAILABLE_CLASS = 'risk-unavailable'

export type RiskSeverity = 'low' | 'moderate' | 'high' | 'critical'

export interface RiskBand {
  severity: RiskSeverity
  /** Displayed severity word. */
  label: string
  /** Modifier class for both the severity text and the bar fill. */
  className: string
  /** Inclusive lower bound of the band. */
  min: number
  /** Inclusive upper bound of the band. */
  max: number
}

export const RISK_BANDS: readonly RiskBand[] = [
  { severity: 'low', label: 'Low', className: 'risk-low', min: 0, max: 24 },
  { severity: 'moderate', label: 'Moderate', className: 'risk-moderate', min: 25, max: 49 },
  { severity: 'high', label: 'High', className: 'risk-high', min: 50, max: 74 },
  { severity: 'critical', label: 'Critical', className: 'risk-critical', min: 75, max: 100 },
]

const clamp = (n: number) => Math.min(100, Math.max(0, Math.round(n)))

/**
 * The integer 0-100 a meter should display, or `null` when the input is not a
 * usable measurement.
 *
 * Unusable (-> null): null, undefined, NaN, and any non-number. These mean "no
 * reading", so they must not resolve to a score.
 * Out of range (-> clamped): ±Infinity and out-of-bounds numbers are ordered
 * values, so they clamp to 0/100 rather than being discarded.
 */
export function normalizeRiskScore(raw: unknown): number | null {
  if (typeof raw !== 'number' || Number.isNaN(raw)) return null
  return clamp(raw)
}

/** Band for a score. Out-of-range values clamp into the nearest band. */
export function riskBand(score: number): RiskBand {
  const n = clamp(score)
  // Bands are contiguous and cover 0-100, so the last one always matches.
  return RISK_BANDS.find(b => n >= b.min && n <= b.max) ?? RISK_BANDS[RISK_BANDS.length - 1]
}

export interface RiskAvailable extends RiskBand {
  available: true
  /** The number to display — the same value the band was derived from. */
  score: number
  /** Fill width as a percentage, equal to the displayed score. */
  percent: number
}

export interface RiskUnavailable {
  available: false
  severity: null
  label: typeof RISK_UNAVAILABLE_LABEL
  className: typeof RISK_UNAVAILABLE_CLASS
}

export type RiskMeterState = RiskAvailable | RiskUnavailable

/**
 * Everything a risk meter needs, derived from one reading.
 *
 * When `available`, render `score` as the number, `label` as the severity, and
 * `className` on the fill; they are guaranteed to describe the same value.
 * When not, render `label` ("Risk unavailable") with no score and no fill.
 */
export function riskMeter(raw: unknown): RiskMeterState {
  const score = normalizeRiskScore(raw)
  if (score === null) {
    return {
      available: false,
      severity: null,
      label: RISK_UNAVAILABLE_LABEL,
      className: RISK_UNAVAILABLE_CLASS,
    }
  }
  return { ...riskBand(score), available: true, score, percent: score }
}
