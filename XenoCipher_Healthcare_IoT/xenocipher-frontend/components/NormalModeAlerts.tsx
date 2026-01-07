'use client'

import React from 'react'
import { useZeroTrust } from '../context/ZeroTrustContext'
import { AnimatePresence } from 'framer-motion'
import { MotionDiv } from '../lib/motion'

/**
 * NormalModeAlerts - Displays informational security alerts in Normal Mode
 * 
 * In Normal Mode:
 * - Alerts are displayed as informational warnings
 * - No encryption changes are made
 * - User is encouraged to activate ZTM for adaptive protection
 * 
 * In ZTM Mode:
 * - This component is hidden (ZTM has its own alert system)
 */
export default function NormalModeAlerts() {
    const { isZeroTrustMode, alerts, dismissAlert, clearAlerts } = useZeroTrust()

    // Don't show in ZTM mode - ZTM has its own alert system
    if (isZeroTrustMode) return null

    const visibleAlerts = alerts.slice(0, 5)

    if (visibleAlerts.length === 0) return null

    return (
        <div className="fixed bottom-4 right-4 z-40 max-w-md w-full space-y-2">
            {/* Header with clear button */}
            <div className="flex items-center justify-between px-3 py-2 bg-yellow-500/20 border border-yellow-500/50 rounded-lg backdrop-blur-sm">
                <div className="flex items-center gap-2 text-yellow-400 text-sm font-mono">
                    <span className="animate-pulse">⚠️</span>
                    <span>SECURITY ALERTS</span>
                    <span className="px-1.5 py-0.5 text-xs bg-yellow-500/30 rounded">
                        {alerts.length}
                    </span>
                </div>
                {alerts.length > 0 && (
                    <button
                        onClick={clearAlerts}
                        className="text-xs text-yellow-400 hover:text-yellow-300 transition-colors"
                    >
                        Clear All
                    </button>
                )}
            </div>

            {/* Alerts List */}
            <AnimatePresence>
                {visibleAlerts.map((alert) => (
                    <MotionDiv
                        key={alert.id}
                        initial={{ opacity: 0, x: 100 }}
                        animate={{ opacity: 1, x: 0 }}
                        exit={{ opacity: 0, x: 100 }}
                        className={`relative p-3 rounded-lg border backdrop-blur-sm ${alert.type === 'critical'
                            ? 'bg-red-500/20 border-red-500/50'
                            : 'bg-yellow-500/20 border-yellow-500/50'
                            }`}
                    >
                        <button
                            onClick={() => dismissAlert(alert.id)}
                            className="absolute top-2 right-2 text-gray-400 hover:text-white text-sm"
                        >
                            ✕
                        </button>

                        <div className="pr-6">
                            <div className="flex items-center gap-2 mb-1">
                                <span className={`text-sm font-bold font-mono ${alert.type === 'critical' ? 'text-red-400' : 'text-yellow-400'
                                    }`}>
                                    {alert.type === 'critical' ? '🚨' : '⚠️'} {alert.attackType}
                                </span>
                            </div>
                            <p className="text-gray-300 text-sm">{alert.message}</p>

                            {alert.metric && (
                                <div className="mt-2 text-xs text-gray-400">
                                    <span className="font-mono">{alert.metric}: </span>
                                    <span className={alert.type === 'critical' ? 'text-red-400' : 'text-yellow-400'}>
                                        {alert.value?.toFixed?.(2) ?? alert.value}
                                    </span>
                                    {alert.threshold && (
                                        <span className="text-gray-500"> (threshold: {alert.threshold})</span>
                                    )}
                                </div>
                            )}

                            {/* Normal Mode Banner */}
                            <div className="mt-2 px-2 py-1 bg-gray-800/80 rounded text-[10px] text-gray-400 flex items-center gap-1">
                                <span>ℹ️</span>
                                <span>Informational only.</span>
                                <span className="text-yellow-400">Activate ZTM</span>
                                <span>for adaptive protection.</span>
                            </div>
                        </div>
                    </MotionDiv>
                ))}
            </AnimatePresence>

            {/* More alerts indicator */}
            {alerts.length > 5 && (
                <div className="text-center text-xs text-gray-500">
                    +{alerts.length - 5} more alerts
                </div>
            )}
        </div>
    )
}
