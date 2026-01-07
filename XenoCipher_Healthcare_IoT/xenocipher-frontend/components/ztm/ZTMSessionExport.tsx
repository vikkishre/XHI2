'use client'

import React, { useState } from 'react'
import { useZeroTrust } from '../../context/ZeroTrustContext'
import { MotionDiv, MotionButton } from '../../lib/motion'

interface ExportFormat {
    name: string
    extension: string
    icon: string
}

const EXPORT_FORMATS: ExportFormat[] = [
    { name: 'JSON', extension: 'json', icon: '📄' },
    { name: 'CSV', extension: 'csv', icon: '📊' }
]

export default function ZTMSessionExport() {
    const {
        activeRecipe,
        heuristics,
        alerts,
        eventLogs,
        isZeroTrustMode,
        lastSwitchTime,
        lastSwitchReason
    } = useZeroTrust()

    const [isExporting, setIsExporting] = useState(false)
    const [lastExport, setLastExport] = useState<string | null>(null)

    const generateExportData = () => {
        return {
            metadata: {
                exportedAt: new Date().toISOString(),
                sessionStart: lastSwitchTime ? new Date(lastSwitchTime).toISOString() : null,
                mode: isZeroTrustMode ? 'ZTM_ACTIVE' : 'NORMAL',
                version: '1.0.0'
            },
            configuration: {
                activeRecipe,
                lastSwitchReason
            },
            heuristics: {
                current: heuristics,
                thresholds: {
                    entropyMin: 7.0,
                    latencyMax: 100,
                    hmacFailuresMax: 10,
                    decryptFailuresMax: 5,
                    replayAttemptsMax: 3
                }
            },
            alerts: alerts.map(a => ({
                ...a,
                timestampISO: new Date(a.timestamp).toISOString()
            })),
            eventLogs: eventLogs.map(l => ({
                ...l,
                timestampISO: new Date(l.timestamp).toISOString()
            })),
            statistics: {
                totalAlerts: alerts.length,
                criticalAlerts: alerts.filter(a => a.type === 'critical').length,
                warningAlerts: alerts.filter(a => a.type === 'warning').length,
                totalEvents: eventLogs.length
            }
        }
    }

    const convertToCSV = (data: ReturnType<typeof generateExportData>) => {
        const lines: string[] = []

        // Metadata section
        lines.push('=== SESSION METADATA ===')
        lines.push(`Exported At,${data.metadata.exportedAt}`)
        lines.push(`Session Start,${data.metadata.sessionStart || 'N/A'}`)
        lines.push(`Mode,${data.metadata.mode}`)
        lines.push(`Active Recipe,${data.configuration.activeRecipe}`)
        lines.push('')

        // Heuristics
        lines.push('=== CURRENT HEURISTICS ===')
        lines.push('Metric,Value')
        Object.entries(data.heuristics.current).forEach(([key, value]) => {
            lines.push(`${key},${value}`)
        })
        lines.push('')

        // Alerts
        lines.push('=== ALERTS ===')
        lines.push('Timestamp,Type,Message')
        data.alerts.forEach(a => {
            lines.push(`${a.timestampISO},${a.type},"${a.message}"`)
        })
        lines.push('')

        // Events
        lines.push('=== EVENT LOG ===')
        lines.push('Timestamp,Type,Source,Message')
        data.eventLogs.forEach(e => {
            lines.push(`${e.timestampISO},${e.type},${e.source},"${e.message}"`)
        })

        return lines.join('\n')
    }

    const handleExport = (format: ExportFormat) => {
        setIsExporting(true)

        try {
            const data = generateExportData()
            let content: string
            let mimeType: string

            if (format.extension === 'json') {
                content = JSON.stringify(data, null, 2)
                mimeType = 'application/json'
            } else {
                content = convertToCSV(data)
                mimeType = 'text/csv'
            }

            const blob = new Blob([content], { type: mimeType })
            const url = URL.createObjectURL(blob)
            const a = document.createElement('a')
            a.href = url
            a.download = `ztm-session-${Date.now()}.${format.extension}`
            a.click()
            URL.revokeObjectURL(url)

            setLastExport(format.name)
        } finally {
            setIsExporting(false)
        }
    }

    return (
        <MotionDiv
            className="bg-gray-900 border border-gray-700 rounded-xl p-4"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
        >
            <h3 className="text-sm font-bold text-gray-300 font-mono mb-3 flex items-center gap-2">
                <span>📥</span> SESSION EXPORT
            </h3>

            {/* Export Buttons */}
            <div className="flex gap-2 mb-3">
                {EXPORT_FORMATS.map(format => (
                    <MotionButton
                        key={format.name}
                        onClick={() => handleExport(format)}
                        disabled={isExporting}
                        className={`flex-1 px-3 py-2 rounded-lg border text-sm font-mono
                            transition-all ${isExporting ? 'opacity-50' : 'hover:border-green-500'}
                            ${lastExport === format.name
                                ? 'bg-green-500/20 border-green-500 text-green-300'
                                : 'bg-gray-800 border-gray-700 text-gray-300'
                            }`}
                        whileHover={{ scale: 1.02 }}
                        whileTap={{ scale: 0.98 }}
                    >
                        <span className="mr-1">{format.icon}</span>
                        {format.name}
                    </MotionButton>
                ))}
            </div>

            {/* Stats Preview */}
            <div className="grid grid-cols-3 gap-2 text-center text-xs">
                <div className="bg-gray-800 rounded p-2">
                    <div className="text-lg font-bold text-white">{alerts.length}</div>
                    <div className="text-gray-500">Alerts</div>
                </div>
                <div className="bg-gray-800 rounded p-2">
                    <div className="text-lg font-bold text-white">{eventLogs.length}</div>
                    <div className="text-gray-500">Events</div>
                </div>
                <div className="bg-gray-800 rounded p-2">
                    <div className="text-lg font-bold text-purple-400">{activeRecipe}</div>
                    <div className="text-gray-500">Recipe</div>
                </div>
            </div>

            {lastExport && (
                <p className="text-[10px] text-green-400 text-center mt-2">
                    ✓ Last exported as {lastExport}
                </p>
            )}
        </MotionDiv>
    )
}
