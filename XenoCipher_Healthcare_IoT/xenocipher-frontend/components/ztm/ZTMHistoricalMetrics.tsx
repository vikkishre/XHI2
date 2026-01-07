'use client'

import React, { useEffect, useState, useRef } from 'react'
import { useZeroTrust } from '../../context/ZeroTrustContext'
import { MotionDiv } from '../../lib/motion'

interface MetricDataPoint {
    timestamp: number
    value: number
}

interface MetricHistory {
    entropyAfter: MetricDataPoint[]
    latencyMs: MetricDataPoint[]
    hmacFailures: MetricDataPoint[]
    replayAttempts: MetricDataPoint[]
}

const MAX_HISTORY_POINTS = 30
const UPDATE_INTERVAL = 2000 // 2 seconds

export default function ZTMHistoricalMetrics() {
    const { heuristics, isZeroTrustMode } = useZeroTrust()
    const [history, setHistory] = useState<MetricHistory>({
        entropyAfter: [],
        latencyMs: [],
        hmacFailures: [],
        replayAttempts: []
    })
    const [selectedMetric, setSelectedMetric] = useState<keyof MetricHistory>('entropyAfter')
    const canvasRef = useRef<HTMLCanvasElement>(null)

    // Record metrics history
    useEffect(() => {
        if (!isZeroTrustMode) return

        const interval = setInterval(() => {
            const now = Date.now()
            setHistory(prev => ({
                entropyAfter: [...prev.entropyAfter.slice(-MAX_HISTORY_POINTS + 1), { timestamp: now, value: heuristics.entropyAfter }],
                latencyMs: [...prev.latencyMs.slice(-MAX_HISTORY_POINTS + 1), { timestamp: now, value: heuristics.latencyMs }],
                hmacFailures: [...prev.hmacFailures.slice(-MAX_HISTORY_POINTS + 1), { timestamp: now, value: heuristics.hmacFailures }],
                replayAttempts: [...prev.replayAttempts.slice(-MAX_HISTORY_POINTS + 1), { timestamp: now, value: heuristics.replayAttempts }]
            }))
        }, UPDATE_INTERVAL)

        return () => clearInterval(interval)
    }, [isZeroTrustMode, heuristics])

    // Draw the graph
    useEffect(() => {
        const canvas = canvasRef.current
        if (!canvas) return

        const ctx = canvas.getContext('2d')
        if (!ctx) return

        const data = history[selectedMetric]
        const width = canvas.width
        const height = canvas.height

        // Clear canvas
        ctx.fillStyle = '#1f2937'
        ctx.fillRect(0, 0, width, height)

        if (data.length < 2) {
            ctx.fillStyle = '#6b7280'
            ctx.font = '12px monospace'
            ctx.textAlign = 'center'
            ctx.fillText('Collecting data...', width / 2, height / 2)
            return
        }

        // Calculate bounds
        const values = data.map(d => d.value)
        const minVal = Math.min(...values) * 0.9
        const maxVal = Math.max(...values) * 1.1 || 1

        // Draw grid lines
        ctx.strokeStyle = '#374151'
        ctx.lineWidth = 1
        for (let i = 0; i <= 4; i++) {
            const y = (height / 4) * i
            ctx.beginPath()
            ctx.moveTo(0, y)
            ctx.lineTo(width, y)
            ctx.stroke()
        }

        // Draw line graph
        const colors: Record<keyof MetricHistory, string> = {
            entropyAfter: '#22c55e',
            latencyMs: '#3b82f6',
            hmacFailures: '#ef4444',
            replayAttempts: '#f59e0b'
        }

        ctx.strokeStyle = colors[selectedMetric]
        ctx.lineWidth = 2
        ctx.lineJoin = 'round'
        ctx.lineCap = 'round'

        ctx.beginPath()
        data.forEach((point, i) => {
            const x = (i / (data.length - 1)) * width
            const y = height - ((point.value - minVal) / (maxVal - minVal)) * height

            if (i === 0) {
                ctx.moveTo(x, y)
            } else {
                ctx.lineTo(x, y)
            }
        })
        ctx.stroke()

        // Draw fill gradient
        const gradient = ctx.createLinearGradient(0, 0, 0, height)
        gradient.addColorStop(0, colors[selectedMetric] + '40')
        gradient.addColorStop(1, 'transparent')

        ctx.fillStyle = gradient
        ctx.beginPath()
        data.forEach((point, i) => {
            const x = (i / (data.length - 1)) * width
            const y = height - ((point.value - minVal) / (maxVal - minVal)) * height

            if (i === 0) {
                ctx.moveTo(x, height)
                ctx.lineTo(x, y)
            } else {
                ctx.lineTo(x, y)
            }
        })
        ctx.lineTo(width, height)
        ctx.closePath()
        ctx.fill()

        // Current value
        const currentVal = values[values.length - 1]
        ctx.fillStyle = '#fff'
        ctx.font = 'bold 14px monospace'
        ctx.textAlign = 'right'
        ctx.fillText(currentVal.toFixed(2), width - 8, 20)

    }, [history, selectedMetric])

    const metricLabels: Record<keyof MetricHistory, string> = {
        entropyAfter: 'Entropy',
        latencyMs: 'Latency (ms)',
        hmacFailures: 'HMAC Fails',
        replayAttempts: 'Replay Attempts'
    }

    if (!isZeroTrustMode) return null

    return (
        <MotionDiv
            className="bg-gray-900 border border-gray-700 rounded-xl p-4"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
        >
            <h3 className="text-sm font-bold text-gray-300 font-mono mb-3 flex items-center gap-2">
                <span>📈</span> HISTORICAL METRICS
                <span className="ml-auto flex items-center gap-1 text-[10px] text-green-400">
                    <span className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></span>
                    LIVE
                </span>
            </h3>

            {/* Metric Selector */}
            <div className="flex gap-1 mb-3">
                {(Object.keys(metricLabels) as (keyof MetricHistory)[]).map(key => (
                    <button
                        key={key}
                        onClick={() => setSelectedMetric(key)}
                        className={`flex-1 px-2 py-1 text-[10px] font-mono rounded transition-colors
                            ${selectedMetric === key
                                ? 'bg-blue-500/30 text-blue-300 border border-blue-500'
                                : 'bg-gray-800 text-gray-400 border border-gray-700 hover:border-gray-500'
                            }`}
                    >
                        {metricLabels[key]}
                    </button>
                ))}
            </div>

            {/* Canvas Graph */}
            <div className="relative">
                <canvas
                    ref={canvasRef}
                    width={300}
                    height={120}
                    className="w-full h-[120px] rounded bg-gray-800"
                />
                <div className="absolute bottom-1 left-2 text-[10px] text-gray-500">
                    Last {MAX_HISTORY_POINTS * UPDATE_INTERVAL / 1000}s
                </div>
            </div>

            {/* Legend */}
            <div className="mt-2 flex justify-between text-[10px] text-gray-500">
                <span>Min: {Math.min(...history[selectedMetric].map(d => d.value) || [0]).toFixed(2)}</span>
                <span>Max: {Math.max(...history[selectedMetric].map(d => d.value) || [0]).toFixed(2)}</span>
            </div>
        </MotionDiv>
    )
}
