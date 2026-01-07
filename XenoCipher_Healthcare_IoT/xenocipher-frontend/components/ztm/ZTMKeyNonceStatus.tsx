'use client'

import React from 'react'
import { motion } from 'framer-motion'

interface ZTMKeyNonceStatusProps {
    keyStatus: {
        initialized: boolean
        lastRegen: number | null
        algorithm: string
    }
    nonceStatus: {
        current: number
        refreshed: boolean
        reuseWarning: boolean
    }
    isZTMEnabled: boolean
}

export default function ZTMKeyNonceStatus({ keyStatus, nonceStatus, isZTMEnabled }: ZTMKeyNonceStatusProps) {
    const formatTime = (timestamp: number | null) => {
        if (!timestamp) return 'Never'
        const seconds = Math.floor((Date.now() - timestamp) / 1000)
        if (seconds < 60) return `${seconds}s ago`
        const minutes = Math.floor(seconds / 60)
        return `${minutes}m ago`
    }

    return (
        <div className="bg-gray-900 border border-gray-700 rounded-xl p-6">
            <h2 className="text-xl font-bold text-red-400 font-mono mb-4 flex items-center gap-2">
                <span>🔑</span> KEY/NONCE STATUS
            </h2>

            <div className="space-y-3">
                {/* Master Key Status */}
                <motion.div
                    className={`p-3 rounded-lg border ${keyStatus.initialized
                            ? 'bg-green-500/20 border-green-500/50'
                            : 'bg-red-500/20 border-red-500/50'
                        }`}
                    whileHover={{ scale: 1.01 }}
                >
                    <div className="flex items-center gap-2 mb-1">
                        <span className={keyStatus.initialized ? 'text-green-400' : 'text-red-400'}>
                            {keyStatus.initialized ? '✓' : '✗'}
                        </span>
                        <span className={`font-mono text-sm ${keyStatus.initialized ? 'text-green-400' : 'text-red-400'}`}>
                            {keyStatus.initialized ? 'Keys Synchronized' : 'Keys Not Initialized'}
                        </span>
                    </div>
                    <div className="text-gray-400 text-xs pl-5">
                        {keyStatus.initialized
                            ? `Master keys active • Regenerated ${formatTime(keyStatus.lastRegen)}`
                            : 'Awaiting key exchange with ESP32'
                        }
                    </div>
                </motion.div>

                {/* Nonce Status */}
                <motion.div
                    className={`p-3 rounded-lg border ${!nonceStatus.reuseWarning
                            ? 'bg-green-500/20 border-green-500/50'
                            : 'bg-yellow-500/20 border-yellow-500/50'
                        }`}
                    whileHover={{ scale: 1.01 }}
                >
                    <div className="flex items-center gap-2 mb-1">
                        <span className={!nonceStatus.reuseWarning ? 'text-green-400' : 'text-yellow-400'}>
                            {!nonceStatus.reuseWarning ? '✓' : '⚠️'}
                        </span>
                        <span className={`font-mono text-sm ${!nonceStatus.reuseWarning ? 'text-green-400' : 'text-yellow-400'}`}>
                            {nonceStatus.refreshed ? 'Nonces Synchronized' : 'Nonce Counter Active'}
                        </span>
                    </div>
                    <div className="text-gray-400 text-xs pl-5">
                        Current nonce: <span className="font-mono">{nonceStatus.current}</span>
                        {nonceStatus.reuseWarning && (
                            <span className="text-yellow-400 ml-2">• Potential reuse detected</span>
                        )}
                    </div>
                </motion.div>

                {/* Recipe Switch Cooldown */}
                <motion.div
                    className="p-3 bg-yellow-500/20 border border-yellow-500/50 rounded-lg"
                    whileHover={{ scale: 1.01 }}
                >
                    <div className="flex items-center gap-2 mb-1">
                        <span className="text-yellow-400">⏱️</span>
                        <span className="font-mono text-sm text-yellow-400">Recipe Switch Cooldown</span>
                    </div>
                    <div className="text-gray-400 text-xs pl-5">
                        5 second minimum between switches to ensure key sync
                    </div>
                </motion.div>

                {/* Algorithm in use */}
                {keyStatus.initialized && (
                    <div className="p-3 bg-gray-800/50 rounded-lg border border-gray-700">
                        <div className="text-xs text-gray-400 mb-1">Active Key Derivation</div>
                        <div className="font-mono text-sm text-blue-400">{keyStatus.algorithm}</div>
                    </div>
                )}
            </div>

            {/* Warnings */}
            {!keyStatus.initialized && (
                <motion.div
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    className="mt-4 p-3 bg-red-500/10 border border-red-500/30 rounded-lg"
                >
                    <p className="text-red-400 text-xs font-mono">
                        ⚠️ Decryption may fail until key exchange completes
                    </p>
                </motion.div>
            )}

            {nonceStatus.reuseWarning && (
                <motion.div
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    className="mt-4 p-3 bg-yellow-500/10 border border-yellow-500/30 rounded-lg"
                >
                    <p className="text-yellow-400 text-xs font-mono">
                        ⚠️ Nonce reuse detected - Security may be compromised
                    </p>
                </motion.div>
            )}
        </div>
    )
}
