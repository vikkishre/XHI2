'use client'

import React, { useState } from 'react'
import { useZeroTrust } from '../../context/ZeroTrustContext'
import { MotionDiv, MotionButton } from '../../lib/motion'

// Predefined threat scenarios for testing
const THREAT_SCENARIOS = [
    {
        name: 'Normal Traffic',
        icon: '🟢',
        heuristics: {
            latencyMs: 45.0,
            entropyAfter: 7.85,
            hmacFailures: 0,
            decryptFailures: 0,
            replayAttempts: 0,
            malformedPackets: 0,
            timingAnomalies: 0
        }
    },
    {
        name: 'Minor Entropy Drop',
        icon: '🟡',
        heuristics: {
            latencyMs: 52.0,
            entropyAfter: 6.8,
            hmacFailures: 1,
            decryptFailures: 0,
            replayAttempts: 0,
            malformedPackets: 2,
            timingAnomalies: 1
        },
        alert: { type: 'warning' as const, message: 'Entropy slightly below optimal threshold' }
    },
    {
        name: 'Replay Attack',
        icon: '🔴',
        heuristics: {
            latencyMs: 65.0,
            entropyAfter: 7.2,
            hmacFailures: 0,
            decryptFailures: 0,
            replayAttempts: 8,
            malformedPackets: 0,
            timingAnomalies: 2
        },
        alert: { type: 'critical' as const, message: 'Replay attack detected - multiple duplicate nonces' }
    },
    {
        name: 'HMAC Failures Spike',
        icon: '🔴',
        heuristics: {
            latencyMs: 78.0,
            entropyAfter: 7.4,
            hmacFailures: 12,
            decryptFailures: 3,
            replayAttempts: 0,
            malformedPackets: 5,
            timingAnomalies: 0
        },
        alert: { type: 'critical' as const, message: 'HMAC validation failures exceeding threshold' }
    },
    {
        name: 'Timing Attack Pattern',
        icon: '🟠',
        heuristics: {
            latencyMs: 120.0,
            entropyAfter: 7.6,
            hmacFailures: 0,
            decryptFailures: 0,
            replayAttempts: 0,
            malformedPackets: 0,
            timingAnomalies: 15
        },
        alert: { type: 'warning' as const, message: 'Timing anomalies suggest potential side-channel analysis' }
    },
    {
        name: 'Full Breach Attempt',
        icon: '💀',
        heuristics: {
            latencyMs: 200.0,
            entropyAfter: 5.5,
            hmacFailures: 25,
            decryptFailures: 18,
            replayAttempts: 12,
            malformedPackets: 30,
            timingAnomalies: 20
        },
        alert: { type: 'critical' as const, message: 'CRITICAL: Active breach attempt - all metrics compromised!' }
    }
]

export default function ZTMDeveloperPanel() {
    const { updateHeuristics, addAlert, addEventLog, isZeroTrustMode } = useZeroTrust()
    const [lastSimulation, setLastSimulation] = useState<string | null>(null)
    const [isExpanded, setIsExpanded] = useState(true)

    const handleSimulate = (scenario: typeof THREAT_SCENARIOS[0]) => {
        // Update heuristics
        updateHeuristics(scenario.heuristics)

        // Add alert if present
        if (scenario.alert) {
            addAlert({
                type: scenario.alert.type,
                message: scenario.alert.message,
                attackType: 'simulation'
            })
        }

        // Log the simulation
        addEventLog({
            type: 'info',
            source: 'system',
            message: `[Dev] Simulated: ${scenario.name}`
        })

        setLastSimulation(scenario.name)
    }

    const handleResetMetrics = () => {
        updateHeuristics({
            latencyMs: 48.5,
            entropyAfter: 7.8,
            hmacFailures: 0,
            decryptFailures: 0,
            replayAttempts: 0,
            malformedPackets: 0,
            timingAnomalies: 0
        })
        setLastSimulation(null)
        addEventLog({
            type: 'info',
            source: 'system',
            message: '[Dev] Metrics reset to baseline'
        })
    }

    if (!isZeroTrustMode) return null

    return (
        <MotionDiv
            className="bg-gray-900 border border-purple-500/50 rounded-xl overflow-hidden"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
        >
            {/* Header */}
            <div
                className="bg-purple-900/30 px-4 py-3 flex items-center justify-between cursor-pointer"
                onClick={() => setIsExpanded(!isExpanded)}
            >
                <div className="flex items-center gap-2">
                    <span className="text-xl">🛠️</span>
                    <h3 className="text-lg font-bold text-purple-400 font-mono">DEV PANEL</h3>
                    <span className="px-2 py-0.5 text-xs bg-purple-500/30 text-purple-300 rounded">TESTING</span>
                </div>
                <span className="text-gray-400">{isExpanded ? '▼' : '▶'}</span>
            </div>

            {isExpanded && (
                <div className="p-4">
                    {/* Scenario Grid */}
                    <div className="grid grid-cols-2 md:grid-cols-3 gap-2 mb-4">
                        {THREAT_SCENARIOS.map((scenario) => (
                            <MotionButton
                                key={scenario.name}
                                onClick={() => handleSimulate(scenario)}
                                className={`p-3 rounded-lg border text-left transition-all
                                    ${lastSimulation === scenario.name
                                        ? 'bg-purple-500/30 border-purple-500'
                                        : 'bg-gray-800 border-gray-700 hover:border-purple-400'
                                    }`}
                                whileHover={{ scale: 1.02 }}
                                whileTap={{ scale: 0.98 }}
                            >
                                <span className="text-lg mr-2">{scenario.icon}</span>
                                <span className="text-xs text-gray-300 font-mono">{scenario.name}</span>
                            </MotionButton>
                        ))}
                    </div>

                    {/* Status & Reset */}
                    <div className="flex items-center justify-between pt-3 border-t border-gray-700">
                        <div className="text-xs text-gray-500">
                            {lastSimulation ? (
                                <span>Last: <span className="text-purple-400">{lastSimulation}</span></span>
                            ) : (
                                <span>No simulation active</span>
                            )}
                        </div>
                        <button
                            onClick={handleResetMetrics}
                            className="px-3 py-1 text-xs bg-gray-800 hover:bg-gray-700 text-gray-300 
                                rounded font-mono border border-gray-600 transition-colors"
                        >
                            Reset to Baseline
                        </button>
                    </div>

                    {/* Warning */}
                    <p className="mt-3 text-[10px] text-gray-600 text-center">
                        ⚠️ Developer testing only. Simulations do not affect actual encryption.
                    </p>
                </div>
            )}
        </MotionDiv>
    )
}
