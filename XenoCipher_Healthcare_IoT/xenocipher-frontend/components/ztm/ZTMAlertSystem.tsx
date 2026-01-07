'use client'

import React, { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'

export interface ThreatAlert {
    id: string
    timestamp: number
    type: 'info' | 'warning' | 'critical'
    attackType: string
    message: string
    metric?: string
    value?: number
    threshold?: number
    recipe?: string  // Recipe switched to (only in ZTM)
}

interface ZTMAlertSystemProps {
    alerts: ThreatAlert[]
    isZTMEnabled: boolean
    maxVisible?: number
    onDismiss?: (id: string) => void
    onDismissAll?: () => void
}

export default function ZTMAlertSystem({
    alerts,
    isZTMEnabled,
    maxVisible = 5,
    onDismiss,
    onDismissAll
}: ZTMAlertSystemProps) {
    const [dismissed, setDismissed] = useState<Set<string>>(new Set())

    const visibleAlerts = alerts
        .filter(a => !dismissed.has(a.id))
        .slice(0, maxVisible)

    const handleDismiss = (id: string) => {
        setDismissed(prev => new Set([...prev, id]))
        onDismiss?.(id)
    }

    const handleDismissAll = () => {
        setDismissed(new Set(alerts.map(a => a.id)))
        onDismissAll?.()
    }

    const getAlertStyle = (type: ThreatAlert['type']) => {
        switch (type) {
            case 'critical':
                return {
                    bg: 'bg-red-500/20',
                    border: 'border-red-500',
                    icon: '🚨',
                    iconBg: 'bg-red-500/30',
                    text: 'text-red-400'
                }
            case 'warning':
                return {
                    bg: 'bg-yellow-500/20',
                    border: 'border-yellow-500',
                    icon: '⚠️',
                    iconBg: 'bg-yellow-500/30',
                    text: 'text-yellow-400'
                }
            default:
                return {
                    bg: 'bg-blue-500/20',
                    border: 'border-blue-500',
                    icon: 'ℹ️',
                    iconBg: 'bg-blue-500/30',
                    text: 'text-blue-400'
                }
        }
    }

    const formatTime = (timestamp: number) => {
        return new Date(timestamp).toLocaleTimeString()
    }

    if (visibleAlerts.length === 0) {
        return (
            <div className="bg-gray-900 border border-gray-700 rounded-xl p-6">
                <h2 className="text-xl font-bold text-red-400 font-mono mb-4 flex items-center gap-2">
                    <span>🚨</span> THREAT ALERTS
                </h2>
                <div className="text-center py-8">
                    <div className="text-4xl mb-2">✅</div>
                    <p className="text-gray-400">No active alerts</p>
                    <p className="text-gray-500 text-sm">System operating normally</p>
                </div>
            </div>
        )
    }

    return (
        <div className="bg-gray-900 border border-gray-700 rounded-xl p-6">
            <div className="flex items-center justify-between mb-4">
                <h2 className="text-xl font-bold text-red-400 font-mono flex items-center gap-2">
                    <span className="animate-pulse">🚨</span> THREAT ALERTS
                    <span className="px-2 py-0.5 text-xs bg-red-500/30 text-red-300 rounded-full">
                        {visibleAlerts.length}
                    </span>
                </h2>
                {visibleAlerts.length > 0 && (
                    <button
                        onClick={handleDismissAll}
                        className="text-xs text-gray-500 hover:text-gray-300 transition-colors"
                    >
                        Clear All
                    </button>
                )}
            </div>

            {/* Mode indicator */}
            <div className={`mb-4 px-3 py-2 rounded-lg text-xs font-mono ${isZTMEnabled
                    ? 'bg-red-500/10 border border-red-500/30 text-red-400'
                    : 'bg-gray-700/50 border border-gray-600 text-gray-400'
                }`}>
                {isZTMEnabled
                    ? '🔴 ZTM Active: Alerts trigger adaptive encryption switching'
                    : '⚪ Normal Mode: Alerts are informational only'
                }
            </div>

            {/* Alerts List */}
            <div className="space-y-2 max-h-80 overflow-y-auto">
                <AnimatePresence mode="popLayout">
                    {visibleAlerts.map((alert, index) => {
                        const style = getAlertStyle(alert.type)

                        return (
                            <motion.div
                                key={alert.id}
                                initial={{ opacity: 0, x: 50, height: 0 }}
                                animate={{ opacity: 1, x: 0, height: 'auto' }}
                                exit={{ opacity: 0, x: -50, height: 0 }}
                                transition={{ duration: 0.2 }}
                                className={`${style.bg} border ${style.border} rounded-lg p-3 relative`}
                            >
                                <button
                                    onClick={() => handleDismiss(alert.id)}
                                    className="absolute top-2 right-2 text-gray-500 hover:text-white transition-colors"
                                >
                                    ✕
                                </button>

                                <div className="flex items-start gap-3 pr-6">
                                    <div className={`w-8 h-8 rounded-full ${style.iconBg} flex items-center justify-center text-lg flex-shrink-0`}>
                                        {style.icon}
                                    </div>

                                    <div className="flex-1 min-w-0">
                                        <div className="flex items-center gap-2 mb-1">
                                            <span className={`font-mono font-bold text-sm ${style.text}`}>
                                                {alert.attackType.toUpperCase()}
                                            </span>
                                            <span className="text-gray-500 text-xs">
                                                {formatTime(alert.timestamp)}
                                            </span>
                                        </div>

                                        <p className="text-gray-300 text-sm mb-2">{alert.message}</p>

                                        {/* Metric details */}
                                        {alert.metric && alert.value !== undefined && (
                                            <div className="text-xs text-gray-400">
                                                <span className="font-mono">{alert.metric}: </span>
                                                <span className={style.text}>{alert.value}</span>
                                                {alert.threshold && (
                                                    <span className="text-gray-500"> (threshold: {alert.threshold})</span>
                                                )}
                                            </div>
                                        )}

                                        {/* Recipe switch info (ZTM only) */}
                                        {isZTMEnabled && alert.recipe && (
                                            <div className="mt-2 px-2 py-1 bg-green-500/20 border border-green-500/30 rounded text-xs">
                                                <span className="text-green-400">⚡ Switched to: </span>
                                                <span className="font-mono text-green-300">{alert.recipe}</span>
                                            </div>
                                        )}
                                    </div>
                                </div>
                            </motion.div>
                        )
                    })}
                </AnimatePresence>
            </div>

            {/* Hidden alerts count */}
            {alerts.length > maxVisible && (
                <div className="mt-3 text-center text-xs text-gray-500">
                    +{alerts.length - maxVisible} more alerts
                </div>
            )}
        </div>
    )
}
