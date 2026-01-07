'use client'

import React from 'react'
import { motion } from 'framer-motion'

interface ESP32Data {
    connected: boolean
    lastSeen: number | null
    encryptedData: string | null
    algorithm: string
}

interface ServerData {
    connected: boolean
    lastSeen: number | null
    decryptedData: string | null
    decryptionTime: number | null
}

interface ZTMESPServerHealthViewProps {
    esp32: ESP32Data
    server: ServerData
    healthData?: {
        heartRate: number
        spo2: number
        steps: number
    }
}

export default function ZTMESPServerHealthView({ esp32, server, healthData }: ZTMESPServerHealthViewProps) {
    const formatTime = (timestamp: number | null) => {
        if (!timestamp) return 'Never'
        const seconds = Math.floor((Date.now() - timestamp) / 1000)
        if (seconds < 10) return 'Just now'
        if (seconds < 60) return `${seconds}s ago`
        const minutes = Math.floor(seconds / 60)
        return `${minutes}m ago`
    }

    const truncateData = (data: string | null, maxLen = 50) => {
        if (!data) return 'No data'
        if (data.length <= maxLen) return data
        return data.substring(0, maxLen) + '...'
    }

    // Check for tampering (if decrypted doesn't match expected pattern)
    const isTamperingDetected = server.decryptedData &&
        !server.decryptedData.includes('[CORRUPTED_DATA]') &&
        !/HR-\d+\s+SPO2-\d+\s+STEPS-\d+/.test(server.decryptedData)

    return (
        <div className="bg-gray-900 border border-gray-700 rounded-xl p-6">
            <h2 className="text-xl font-bold text-red-400 font-mono mb-4 flex items-center gap-2">
                <span>📡</span> ESP32-SERVER DATA VIEW
            </h2>

            {/* Connection Status */}
            <div className="flex gap-4 mb-4">
                <div className={`flex-1 p-3 rounded-lg border ${esp32.connected ? 'bg-green-500/10 border-green-500/50' : 'bg-red-500/10 border-red-500/50'
                    }`}>
                    <div className="flex items-center gap-2 mb-1">
                        <div className={`w-2 h-2 rounded-full ${esp32.connected ? 'bg-green-400 animate-pulse' : 'bg-red-400'}`} />
                        <span className="font-mono text-sm text-gray-300">ESP32</span>
                    </div>
                    <p className={`text-xs ${esp32.connected ? 'text-green-400' : 'text-red-400'}`}>
                        {esp32.connected ? 'Connected' : 'Disconnected'}
                    </p>
                    <p className="text-xs text-gray-500">Last: {formatTime(esp32.lastSeen)}</p>
                </div>

                <div className={`flex-1 p-3 rounded-lg border ${server.connected ? 'bg-green-500/10 border-green-500/50' : 'bg-red-500/10 border-red-500/50'
                    }`}>
                    <div className="flex items-center gap-2 mb-1">
                        <div className={`w-2 h-2 rounded-full ${server.connected ? 'bg-green-400 animate-pulse' : 'bg-red-400'}`} />
                        <span className="font-mono text-sm text-gray-300">Server</span>
                    </div>
                    <p className={`text-xs ${server.connected ? 'text-green-400' : 'text-red-400'}`}>
                        {server.connected ? 'Connected' : 'Disconnected'}
                    </p>
                    <p className="text-xs text-gray-500">Last: {formatTime(server.lastSeen)}</p>
                </div>
            </div>

            {/* Data Comparison */}
            <div className="space-y-3">
                {/* Encrypted Data (ESP32) */}
                <div className="p-3 bg-gray-800/50 rounded-lg border border-cyan-500/30">
                    <div className="flex items-center gap-2 mb-2">
                        <span className="text-cyan-400">🔒</span>
                        <span className="text-cyan-400 font-mono text-xs">ESP32 Encrypted</span>
                        {esp32.algorithm && (
                            <span className="px-1.5 py-0.5 bg-cyan-500/20 text-cyan-300 text-[10px] rounded">
                                {esp32.algorithm}
                            </span>
                        )}
                    </div>
                    <code className="block text-xs text-gray-400 break-all font-mono bg-gray-900/50 p-2 rounded">
                        {truncateData(esp32.encryptedData)}
                    </code>
                </div>

                {/* Arrow */}
                <div className="flex justify-center">
                    <motion.div
                        animate={{ y: [0, 5, 0] }}
                        transition={{ repeat: Infinity, duration: 1 }}
                        className="text-gray-500"
                    >
                        ↓
                    </motion.div>
                </div>

                {/* Decrypted Data (Server) */}
                <div className={`p-3 rounded-lg border ${isTamperingDetected
                        ? 'bg-red-500/10 border-red-500/50'
                        : 'bg-green-500/10 border-green-500/50'
                    }`}>
                    <div className="flex items-center gap-2 mb-2">
                        <span className="text-green-400">🔓</span>
                        <span className={`${isTamperingDetected ? 'text-red-400' : 'text-green-400'} font-mono text-xs`}>
                            Server Decrypted
                        </span>
                        {server.decryptionTime && (
                            <span className="px-1.5 py-0.5 bg-blue-500/20 text-blue-300 text-[10px] rounded">
                                {server.decryptionTime.toFixed(2)}ms
                            </span>
                        )}
                        {isTamperingDetected && (
                            <span className="px-1.5 py-0.5 bg-red-500/30 text-red-300 text-[10px] rounded animate-pulse">
                                ⚠️ TAMPERING DETECTED
                            </span>
                        )}
                    </div>
                    <code className={`block text-xs break-all font-mono p-2 rounded ${isTamperingDetected ? 'text-red-400 bg-red-900/30' : 'text-gray-300 bg-gray-900/50'
                        }`}>
                        {truncateData(server.decryptedData)}
                    </code>
                </div>
            </div>

            {/* Health Data Display */}
            {healthData && healthData.heartRate > 0 && (
                <div className="mt-4 pt-4 border-t border-gray-700">
                    <h3 className="text-sm font-mono text-gray-400 mb-3">PARSED HEALTH DATA</h3>
                    <div className="grid grid-cols-3 gap-3">
                        <motion.div
                            className="p-3 bg-pink-500/10 border border-pink-500/30 rounded-lg text-center"
                            whileHover={{ scale: 1.02 }}
                        >
                            <div className="text-2xl mb-1">💓</div>
                            <div className="text-xl font-bold text-pink-400">{healthData.heartRate}</div>
                            <div className="text-xs text-gray-500">BPM</div>
                        </motion.div>

                        <motion.div
                            className="p-3 bg-blue-500/10 border border-blue-500/30 rounded-lg text-center"
                            whileHover={{ scale: 1.02 }}
                        >
                            <div className="text-2xl mb-1">🩸</div>
                            <div className="text-xl font-bold text-blue-400">{healthData.spo2}%</div>
                            <div className="text-xs text-gray-500">SpO2</div>
                        </motion.div>

                        <motion.div
                            className="p-3 bg-green-500/10 border border-green-500/30 rounded-lg text-center"
                            whileHover={{ scale: 1.02 }}
                        >
                            <div className="text-2xl mb-1">👟</div>
                            <div className="text-xl font-bold text-green-400">{healthData.steps}</div>
                            <div className="text-xs text-gray-500">Steps</div>
                        </motion.div>
                    </div>
                </div>
            )}
        </div>
    )
}
