// lib/heuristics-thresholds.ts
// Threshold definitions from heuristics.json for real-time alert generation

export interface ThresholdRule {
    metric: string
    operator: '>' | '<' | '>=' | '<='
    threshold: number
    type: 'absolute' | 'zscore'
    confidenceWeight: number
}

export interface AttackProfile {
    name: string
    displayName: string
    rules: ThresholdRule[]
    aggregation: 'OR' | 'AND'
    minConfidence: number
    targetRecipe: string
    reason: string
    severity: 'warning' | 'critical'
    cooldownSeconds: number
}

// Attack profiles derived from heuristics.json
export const ATTACK_PROFILES: AttackProfile[] = [
    {
        name: 'udp_flood',
        displayName: 'UDP Flood Attack',
        rules: [
            { metric: 'latencyMs', operator: '>', threshold: 55.0, type: 'absolute', confidenceWeight: 1.0 }
        ],
        aggregation: 'OR',
        minConfidence: 0.80,
        targetRecipe: 'CHAOS_ONLY',
        reason: 'Network DoS detected - maintain baseline security',
        severity: 'critical',
        cooldownSeconds: 30
    },
    {
        name: 'tcp_syn_flood',
        displayName: 'TCP SYN Flood',
        rules: [
            { metric: 'memoryPercent', operator: '>', threshold: 0.22, type: 'absolute', confidenceWeight: 0.9 },
            { metric: 'latencyMs', operator: '>', threshold: 54.0, type: 'absolute', confidenceWeight: 0.6 }
        ],
        aggregation: 'AND',
        minConfidence: 0.75,
        targetRecipe: 'CHAOS_ONLY',
        reason: 'TCP SYN flood detected - maintain baseline security',
        severity: 'critical',
        cooldownSeconds: 60
    },
    {
        name: 'timing_attack',
        displayName: 'Timing Side-Channel',
        rules: [
            { metric: 'timingAnomalies', operator: '>', threshold: 5, type: 'absolute', confidenceWeight: 0.9 }
        ],
        aggregation: 'OR',
        minConfidence: 0.85,
        targetRecipe: 'SALSA_LIGHT',
        reason: 'Timing side-channel detected - switch to constant-time cipher',
        severity: 'warning',
        cooldownSeconds: 45
    },
    {
        name: 'rng_manipulation',
        displayName: 'RNG Manipulation',
        rules: [
            { metric: 'entropyAfter', operator: '<', threshold: 6.5, type: 'absolute', confidenceWeight: 0.99 }
        ],
        aggregation: 'OR',
        minConfidence: 0.90,
        targetRecipe: 'FULL_STACK',
        reason: 'RNG manipulation detected - switch to all-security mode',
        severity: 'critical',
        cooldownSeconds: 120
    },
    {
        name: 'hmac_breach',
        displayName: 'HMAC Integrity Breach',
        rules: [
            { metric: 'hmacFailures', operator: '>', threshold: 5, type: 'absolute', confidenceWeight: 1.0 }
        ],
        aggregation: 'OR',
        minConfidence: 0.95,
        targetRecipe: 'FULL_STACK',
        reason: 'HMAC failures detected - possible tampering',
        severity: 'critical',
        cooldownSeconds: 60
    },
    {
        name: 'replay_attempt',
        displayName: 'Replay Attack',
        rules: [
            { metric: 'replayAttempts', operator: '>', threshold: 3, type: 'absolute', confidenceWeight: 1.0 }
        ],
        aggregation: 'OR',
        minConfidence: 0.95,
        targetRecipe: 'CHACHA_HEAVY',
        reason: 'Replay attack detected - switch to stronger cipher',
        severity: 'critical',
        cooldownSeconds: 30
    },
    {
        name: 'decrypt_failures',
        displayName: 'Decryption Failures',
        rules: [
            { metric: 'decryptFailures', operator: '>', threshold: 3, type: 'absolute', confidenceWeight: 0.9 }
        ],
        aggregation: 'OR',
        minConfidence: 0.85,
        targetRecipe: 'CHAOS_ONLY',
        reason: 'Decryption failures indicate potential key mismatch or attack',
        severity: 'warning',
        cooldownSeconds: 45
    }
]

// Baseline thresholds for warning level alerts (softer thresholds)
export const WARNING_THRESHOLDS = {
    latencyMs: { warning: 52, critical: 55 },
    entropyAfter: { warning: 7.2, critical: 6.5 },
    hmacFailures: { warning: 2, critical: 5 },
    decryptFailures: { warning: 1, critical: 3 },
    replayAttempts: { warning: 1, critical: 3 },
    malformedPackets: { warning: 3, critical: 10 },
    timingAnomalies: { warning: 3, critical: 5 }
}

export interface HeuristicMetrics {
    latencyMs: number
    entropyAfter: number
    memoryPercent: number
    cpuPercent: number
    hmacFailures: number
    decryptFailures: number
    replayAttempts: number
    malformedPackets: number
    timingAnomalies: number
}

export interface AlertTrigger {
    profile: AttackProfile
    triggeredRules: ThresholdRule[]
    confidence: number
    value: number
    threshold: number
    metric: string
}

// Check a single metric against a rule
function checkRule(metrics: HeuristicMetrics, rule: ThresholdRule): boolean {
    const metricValue = metrics[rule.metric as keyof HeuristicMetrics] as number
    if (metricValue === undefined) return false

    switch (rule.operator) {
        case '>': return metricValue > rule.threshold
        case '<': return metricValue < rule.threshold
        case '>=': return metricValue >= rule.threshold
        case '<=': return metricValue <= rule.threshold
        default: return false
    }
}

// Check metrics against all attack profiles
export function checkThresholds(metrics: HeuristicMetrics): AlertTrigger[] {
    const triggers: AlertTrigger[] = []

    for (const profile of ATTACK_PROFILES) {
        const triggeredRules: ThresholdRule[] = []
        let totalWeight = 0
        let triggeredWeight = 0

        for (const rule of profile.rules) {
            totalWeight += rule.confidenceWeight
            if (checkRule(metrics, rule)) {
                triggeredRules.push(rule)
                triggeredWeight += rule.confidenceWeight
            }
        }

        const confidence = totalWeight > 0 ? triggeredWeight / totalWeight : 0
        const shouldTrigger = profile.aggregation === 'OR'
            ? triggeredRules.length > 0 && confidence >= profile.minConfidence
            : triggeredRules.length === profile.rules.length && confidence >= profile.minConfidence

        if (shouldTrigger && triggeredRules.length > 0) {
            const firstRule = triggeredRules[0]
            const metricValue = metrics[firstRule.metric as keyof HeuristicMetrics] as number

            triggers.push({
                profile,
                triggeredRules,
                confidence,
                value: metricValue,
                threshold: firstRule.threshold,
                metric: firstRule.metric
            })
        }
    }

    return triggers
}

// Track cooldowns to prevent alert spam
const alertCooldowns: Map<string, number> = new Map()

export function canTriggerAlert(profileName: string, cooldownSeconds: number): boolean {
    const now = Date.now()
    const lastTriggered = alertCooldowns.get(profileName) || 0

    if (now - lastTriggered < cooldownSeconds * 1000) {
        return false
    }

    alertCooldowns.set(profileName, now)
    return true
}

// Reset cooldown for a profile
export function resetCooldown(profileName: string): void {
    alertCooldowns.delete(profileName)
}
