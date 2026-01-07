'use client'

import React from 'react'
import { motion } from 'framer-motion'
import { ZTMRecipeKey, RECIPE_DEFINITIONS } from './ZTMRecipesPanel'

interface ZTMActiveRecipeDetailsProps {
    activeRecipe: ZTMRecipeKey
    switchReason?: string
    switchedAt?: number
}

const ALGORITHM_INFO: Record<string, { description: string; icon: string; color: string }> = {
    LFSR: {
        description: 'Linear Feedback Shift Register with chaotic tap adaptation',
        icon: '🔄',
        color: 'cyan'
    },
    Tinkerbell: {
        description: 'Chaotic Tinkerbell map for XOR keystream generation',
        icon: '✨',
        color: 'purple'
    },
    ChaCha20: {
        description: 'ARX-based stream cipher, constant-time operations',
        icon: '⚡',
        color: 'yellow'
    },
    Salsa20: {
        description: 'High-speed stream cipher, low memory footprint',
        icon: '💨',
        color: 'green'
    },
    Transposition: {
        description: 'Chaotic grid permutation with position shuffling',
        icon: '🔀',
        color: 'pink'
    }
}

export default function ZTMActiveRecipeDetails({
    activeRecipe,
    switchReason,
    switchedAt
}: ZTMActiveRecipeDetailsProps) {
    const recipe = RECIPE_DEFINITIONS[activeRecipe]

    const timeSinceSwitch = switchedAt
        ? Math.floor((Date.now() - switchedAt) / 1000)
        : null

    return (
        <div className="bg-gray-900 border border-gray-700 rounded-xl p-6">
            <h2 className="text-xl font-bold text-red-400 font-mono mb-4 flex items-center gap-2">
                <span>🎯</span> ACTIVE RECIPE DETAILS
            </h2>

            {/* Recipe Header */}
            <div className="mb-6">
                <div className="flex items-center gap-3 mb-2">
                    <span className="text-3xl">{recipe.icon}</span>
                    <div>
                        <h3 className="text-2xl font-bold text-white font-mono">{recipe.name}</h3>
                        <p className="text-gray-400 text-sm">{recipe.description}</p>
                    </div>
                </div>

                {/* Stats Bar */}
                <div className="flex items-center gap-4 mt-3">
                    <div className="px-3 py-1 bg-red-500/20 border border-red-500/50 rounded text-red-400 text-xs font-mono">
                        Security: {recipe.securityLevel.toUpperCase()}
                    </div>
                    <div className="px-3 py-1 bg-blue-500/20 border border-blue-500/50 rounded text-blue-400 text-xs font-mono">
                        CPU: {recipe.cpuOverhead}%
                    </div>
                    {timeSinceSwitch !== null && (
                        <div className="px-3 py-1 bg-gray-700/50 border border-gray-600 rounded text-gray-400 text-xs font-mono">
                            Active: {timeSinceSwitch}s ago
                        </div>
                    )}
                </div>
            </div>

            {/* Switch Reason */}
            {switchReason && (
                <motion.div
                    initial={{ opacity: 0, y: -10 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="mb-6 p-3 bg-yellow-500/10 border border-yellow-500/30 rounded-lg"
                >
                    <div className="flex items-start gap-2">
                        <span className="text-yellow-400">⚡</span>
                        <div>
                            <p className="text-yellow-400 text-sm font-mono font-bold mb-1">Adaptive Switch Reason</p>
                            <p className="text-gray-300 text-xs">{switchReason}</p>
                        </div>
                    </div>
                </motion.div>
            )}

            {/* Algorithm Pipeline */}
            <div className="space-y-2">
                <h4 className="text-sm font-mono text-gray-400 mb-3">ENCRYPTION PIPELINE</h4>

                {recipe.algorithms.map((alg, idx) => {
                    const algInfo = ALGORITHM_INFO[alg] || {
                        description: 'Cryptographic algorithm',
                        icon: '🔐',
                        color: 'gray'
                    }

                    return (
                        <motion.div
                            key={alg}
                            initial={{ opacity: 0, x: -20 }}
                            animate={{ opacity: 1, x: 0 }}
                            transition={{ delay: idx * 0.1 }}
                            className="flex items-center gap-3 p-3 bg-gray-800/50 rounded-lg border border-gray-700"
                        >
                            {/* Step Number */}
                            <div className={`w-8 h-8 rounded-full flex items-center justify-center text-white font-bold text-sm
                bg-${algInfo.color}-500/30 border-2 border-${algInfo.color}-500/50`}
                                style={{
                                    backgroundColor: `var(--${algInfo.color}-500, rgba(34, 211, 238, 0.3))`,
                                    borderColor: `var(--${algInfo.color}-500, rgba(34, 211, 238, 0.5))`
                                }}
                            >
                                {idx + 1}
                            </div>

                            {/* Algorithm Icon */}
                            <span className="text-2xl">{algInfo.icon}</span>

                            {/* Algorithm Info */}
                            <div className="flex-1">
                                <div className="font-mono font-bold text-white mb-0.5">{alg}</div>
                                <div className="text-gray-400 text-xs">{algInfo.description}</div>
                            </div>

                            {/* Active Indicator */}
                            <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
                        </motion.div>
                    )
                })}

                {/* Arrow indicators between steps */}
                {recipe.algorithms.length > 1 && (
                    <div className="absolute left-11 top-0 bottom-0 w-0.5 bg-gradient-to-b from-cyan-500 via-purple-500 to-green-500 opacity-30" />
                )}
            </div>

            {/* Use Case Footer */}
            <div className="mt-4 pt-4 border-t border-gray-700">
                <p className="text-xs text-gray-500">
                    <span className="text-yellow-400">💡 Optimal for:</span> {recipe.useCase}
                </p>
            </div>
        </div>
    )
}
