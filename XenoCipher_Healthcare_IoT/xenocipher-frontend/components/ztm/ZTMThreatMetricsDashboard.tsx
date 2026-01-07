'use client'

import React from 'react'
import { motion } from 'framer-motion'

export interface HeuristicMetrics {
    latencyMs: number
    entropyAfter: number
    memoryPercent: number
    cpuPercent: number
    // Additional threat counters
    hmacFailures: number
    decryptFailures: number
    replayAttempts: number
    malformedPackets: number
    timingAnomalies: number
}

interface ZTMThreatMetricsDashboardProps {
    metrics: HeuristicMetrics
    isZTMEnabled: boolean
    onThresholdBreach?: (attackType: string, metric: string, value: number) => void
}

// Thresholds from heuristics.json baseline
const THRESHOLDS = {
    latencyMs: { safe: 55.0, warning: 52.0, baseline: 48.5 },
    entropyAfter: { safe: 7.5, warning: 7.6, baseline: 7.8 },
    memoryPercent: { safe: 0.22, warning: 0.21, baseline: 0.204 },
    cpuPercent: { safe: 5.0, warning: 3.0, baseline: 0.0 },
    hmacFailures: { safe: 3, warning: 1 },
    decryptFailures: { safe: 3, warning: 1 },
    replayAttempts: { safe: 2, warning: 1 },
    malformedPackets: { safe: 5, warning: 2 },
    timingAnomalies: { safe: 10, warning: 5 }
}

export default function ZTMThreatMetricsDashboard({
    metrics,
    isZTMEnabled,
    onThresholdBreach
}: ZTMThreatMetricsDashboardProps) {

    const getMetricStatus = (value: number, thresholds: { safe: number; warning: number; baseline?: number }, isLowerBetter = false) => {
        if (isLowerBetter) {
            if (value <= thresholds.warning) return { status: 'safe', color: 'green' }
            if (value <= thresholds.safe) return { status: 'warning', color: 'yellow' }
            return { status: 'danger', color: 'red' }
        } else {
            if (value >= thresholds.warning) return { status: 'safe', color: 'green' }
            if (value >= thresholds.safe) return { status: 'warning', color: 'yellow' }
            return { status: 'danger', color: 'red' }
        }
    }

    const getCounterStatus = (value: number, thresholds: { safe: number; warning: number }) => {
        if (value === 0) return { status: 'safe', color: 'green' }
        if (value <= thresholds.warning) return { status: 'warning', color: 'yellow' }
        if (value <= thresholds.safe) return { status: 'elevated', color: 'orange' }
        return { status: 'danger', color: 'red' }
    }

    const renderProgressBar = (
        label: string,
        value: number,
        max: number,
        unit: string,
        thresholds: { safe: number; warning: number; baseline?: number },
        isLowerBetter = false
    ) => {
        const { status, color } = getMetricStatus(value, thresholds, isLowerBetter)
        const percentage = Math.min((value / max) * 100, 100)

        const colorClasses = {
            green: 'bg-green-500',
            yellow: 'bg-yellow-500',
            orange: 'bg-orange-500',
            red: 'bg-red-500'
        }

        return (
            <div className="mb-4">
                <div className="flex justify-between mb-1">
                    <span className="text-gray-400 text-sm">{label}</span>
                    <span className={`font-mono text-sm text-${color}-400`}>
                        {value.toFixed(2)} {unit}
                    </span>
                </div>
                <div className="w-full bg-gray-800 rounded-full h-2 relative overflow-hidden">
                    <motion.div
                        className={`h-2 rounded-full ${colorClasses[color as keyof typeof colorClasses]}`}
                        initial={{ width: 0 }}
                        animate={{ width: `${percentage}%` }}
                        transition={{ duration: 0.5 }}
                    />
                    {/* Threshold markers */}
                    {thresholds.baseline && (
                        <div
                            className="absolute top-0 h-full w-0.5 bg-blue-400/50"
                            style={{ left: `${(thresholds.baseline / max) * 100}%` }}
                            title={`Baseline: ${thresholds.baseline}`}
                        />
                    )}
                    <div
                        className="absolute top-0 h-full w-0.5 bg-yellow-400/50"
                        style={{ left: `${(thresholds.warning / max) * 100}%` }}
                        title={`Warning: ${thresholds.warning}`}
                    />
                    <div
                        className="absolute top-0 h-full w-0.5 bg-red-400/50"
                        style={{ left: `${(thresholds.safe / max) * 100}%` }}
                        title={`Critical: ${thresholds.safe}`}
                    />
                </div>
            </div>
        )
    }

    const renderCounter = (label: string, value: number, thresholds: { safe: number; warning: number }) => {
        const { status, color } = getCounterStatus(value, thresholds)

        const colorClasses = {
            green: 'border-green-500/50 text-green-400',
            yellow: 'border-yellow-500/50 text-yellow-400',
            orange: 'border-orange-500/50 text-orange-400',
            red: 'border-red-500/50 text-red-400'
        }

        return (
            <motion.div
                className={`p-3 bg-gray-800/50 rounded-lg border ${colorClasses[color as keyof typeof colorClasses]}`}
                whileHover={{ scale: 1.02 }}
            >
                <div className="text-xs text-gray-400 mb-1">{label}</div>
                <div className="text-2xl font-mono font-bold">{value}</div>
            </motion.div>
        )
    }

    const overallThreat = () => {
        const dangerCount = [
            metrics.hmacFailures > THRESHOLDS.hmacFailures.safe,
            metrics.decryptFailures > THRESHOLDS.decryptFailures.safe,
            metrics.replayAttempts > THRESHOLDS.replayAttempts.safe,
            metrics.latencyMs > THRESHOLDS.latencyMs.safe,
            metrics.memoryPercent > THRESHOLDS.memoryPercent.safe
        ].filter(Boolean).length

        if (dangerCount >= 2) return { level: 'CRITICAL', color: 'red' }
        if (dangerCount >= 1) return { level: 'ELEVATED', color: 'yellow' }
        return { level: 'NORMAL', color: 'green' }
    }

    const threat = overallThreat()

    return (
        <div className="bg-gray-900 border border-gray-700 rounded-xl p-6">
            <div className="flex items-center justify-between mb-6">
                <h2 className="text-xl font-bold text-red-400 font-mono flex items-center gap-2">
                    <span>📈</span> THREAT METRICS
                </h2>
                <div className={`px-3 py-1 rounded-lg border
          ${threat.color === 'red' ? 'bg-red-500/20 border-red-500 text-red-400' :
                        threat.color === 'yellow' ? 'bg-yellow-500/20 border-yellow-500 text-yellow-400' :
                            'bg-green-500/20 border-green-500 text-green-400'}`}
                >
                    <span className="font-mono text-sm font-bold">{threat.level}</span>
                </div>
            </div>

            {/* System Metrics */}
            <div className="mb-6">
                <h3 className="text-sm font-mono text-gray-500 mb-3">SYSTEM METRICS</h3>
                {renderProgressBar('Latency', metrics.latencyMs, 100, 'ms', THRESHOLDS.latencyMs, true)}
                {renderProgressBar('Entropy', metrics.entropyAfter, 8, 'bits', THRESHOLDS.entropyAfter, false)}
                {renderProgressBar('Memory', metrics.memoryPercent * 100, 100, '%',
                    { safe: THRESHOLDS.memoryPercent.safe * 100, warning: THRESHOLDS.memoryPercent.warning * 100, baseline: THRESHOLDS.memoryPercent.baseline * 100 }, true)}
                {renderProgressBar('CPU', metrics.cpuPercent, 100, '%', THRESHOLDS.cpuPercent, true)}
            </div>

            {/* Security Counters */}
            <div>
                <h3 className="text-sm font-mono text-gray-500 mb-3">SECURITY EVENTS</h3>
                <div className="grid grid-cols-3 gap-2">
                    {renderCounter('HMAC Failures', metrics.hmacFailures, THRESHOLDS.hmacFailures)}
                    {renderCounter('Decrypt Failures', metrics.decryptFailures, THRESHOLDS.decryptFailures)}
                    {renderCounter('Replay Attempts', metrics.replayAttempts, THRESHOLDS.replayAttempts)}
                    {renderCounter('Malformed Pkts', metrics.malformedPackets, THRESHOLDS.malformedPackets)}
                    {renderCounter('Timing Anomalies', metrics.timingAnomalies, THRESHOLDS.timingAnomalies)}
                </div>
            </div>

            {/* ZTM Status */}
            <div className="mt-4 pt-4 border-t border-gray-700">
                <div className="flex items-center justify-between text-xs">
                    <span className="text-gray-500">
                        {isZTMEnabled ? '🔴 ZTM Active - Auto-switching enabled' : '⚪ Normal Mode - Alerts only'}
                    </span>
                    <span className="text-gray-600">
                        Updated: {new Date().toLocaleTimeString()}
                    </span>
                </div>
            </div>
        </div>
    )
}
