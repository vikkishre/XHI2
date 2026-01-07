'use client'

import React, { useRef, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'

export interface LogEntry {
    id: string
    timestamp: number
    type: 'info' | 'success' | 'warning' | 'error' | 'threat' | 'recipe_switch' | 'health'
    message: string
    source: 'esp32' | 'server' | 'pipeline' | 'ztm' | 'system'
    details?: Record<string, unknown>
}

interface ZTMEventLogProps {
    logs: LogEntry[]
    maxHeight?: string
    onClear?: () => void
    onExport?: () => void
}

export default function ZTMEventLog({
    logs,
    maxHeight = '300px',
    onClear,
    onExport
}: ZTMEventLogProps) {
    const logEndRef = useRef<HTMLDivElement>(null)

    // Auto-scroll to bottom on new logs
    useEffect(() => {
        logEndRef.current?.scrollIntoView({ behavior: 'smooth' })
    }, [logs])

    const getLogStyle = (type: LogEntry['type']) => {
        switch (type) {
            case 'success':
                return { icon: '✅', color: 'text-green-400', bg: 'bg-green-500/10' }
            case 'warning':
                return { icon: '⚠️', color: 'text-yellow-400', bg: 'bg-yellow-500/10' }
            case 'error':
                return { icon: '❌', color: 'text-red-400', bg: 'bg-red-500/10' }
            case 'threat':
                return { icon: '🚨', color: 'text-red-400', bg: 'bg-red-500/20' }
            case 'recipe_switch':
                return { icon: '⚡', color: 'text-purple-400', bg: 'bg-purple-500/10' }
            case 'health':
                return { icon: '💓', color: 'text-pink-400', bg: 'bg-pink-500/10' }
            default:
                return { icon: 'ℹ️', color: 'text-blue-400', bg: 'bg-blue-500/10' }
        }
    }

    const getSourceBadge = (source: LogEntry['source']) => {
        switch (source) {
            case 'esp32':
                return { label: 'ESP32', color: 'bg-cyan-500/30 text-cyan-300' }
            case 'server':
                return { label: 'SERVER', color: 'bg-green-500/30 text-green-300' }
            case 'pipeline':
                return { label: 'PIPELINE', color: 'bg-yellow-500/30 text-yellow-300' }
            case 'ztm':
                return { label: 'ZTM', color: 'bg-red-500/30 text-red-300' }
            default:
                return { label: 'SYSTEM', color: 'bg-gray-500/30 text-gray-300' }
        }
    }

    const formatTime = (timestamp: number) => {
        return new Date(timestamp).toLocaleTimeString('en-US', {
            hour12: false,
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
        }) + '.' + String(timestamp % 1000).padStart(3, '0')
    }

    return (
        <div className="bg-gray-900 border border-gray-700 rounded-xl p-6">
            <div className="flex items-center justify-between mb-4">
                <h2 className="text-xl font-bold text-red-400 font-mono flex items-center gap-2">
                    <span>📜</span> LIVE EVENT LOG
                    <span className="px-2 py-0.5 text-xs bg-gray-700 text-gray-300 rounded-full font-normal">
                        {logs.length}
                    </span>
                </h2>
                <div className="flex gap-2">
                    {onExport && (
                        <button
                            onClick={onExport}
                            className="px-3 py-1 text-xs font-mono bg-gray-800 hover:bg-gray-700 text-gray-300 rounded border border-gray-700 transition-colors"
                        >
                            📥 Export
                        </button>
                    )}
                    {onClear && (
                        <button
                            onClick={onClear}
                            className="px-3 py-1 text-xs font-mono bg-gray-800 hover:bg-gray-700 text-gray-300 rounded border border-gray-700 transition-colors"
                        >
                            🗑️ Clear
                        </button>
                    )}
                </div>
            </div>

            <div
                className="space-y-1 overflow-y-auto font-mono text-xs"
                style={{ maxHeight }}
            >
                {logs.length === 0 ? (
                    <div className="text-center py-8 text-gray-500">
                        <div className="text-2xl mb-2">📋</div>
                        <p>No events logged yet</p>
                    </div>
                ) : (
                    <AnimatePresence mode="popLayout">
                        {logs.map((log) => {
                            const style = getLogStyle(log.type)
                            const source = getSourceBadge(log.source)

                            return (
                                <motion.div
                                    key={log.id}
                                    initial={{ opacity: 0, x: -20 }}
                                    animate={{ opacity: 1, x: 0 }}
                                    exit={{ opacity: 0, height: 0 }}
                                    className={`${style.bg} p-2 rounded border border-gray-800 hover:border-gray-700 transition-colors`}
                                >
                                    <div className="flex items-start gap-2">
                                        {/* Timestamp */}
                                        <span className="text-gray-500 flex-shrink-0 w-24">
                                            {formatTime(log.timestamp)}
                                        </span>

                                        {/* Source Badge */}
                                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold flex-shrink-0 ${source.color}`}>
                                            {source.label}
                                        </span>

                                        {/* Icon */}
                                        <span className="flex-shrink-0">{style.icon}</span>

                                        {/* Message */}
                                        <span className={`${style.color} flex-1 break-words`}>
                                            {log.message}
                                        </span>
                                    </div>

                                    {/* Details (expandable) */}
                                    {log.details && Object.keys(log.details).length > 0 && (
                                        <div className="mt-1 ml-28 text-gray-500 text-[10px]">
                                            {Object.entries(log.details).map(([key, value]) => (
                                                <span key={key} className="mr-3">
                                                    <span className="text-gray-600">{key}:</span> {String(value)}
                                                </span>
                                            ))}
                                        </div>
                                    )}
                                </motion.div>
                            )
                        })}
                    </AnimatePresence>
                )}
                <div ref={logEndRef} />
            </div>
        </div>
    )
}
