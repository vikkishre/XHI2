'use client'

import React from 'react'
import { motion } from 'framer-motion'

export type ZTMRecipeKey = 'FULL_STACK' | 'CHACHA_HEAVY' | 'SALSA_LIGHT' | 'CHAOS_ONLY' | 'STREAM_FOCUS'

export interface RecipeDefinition {
    name: string
    algorithms: string[]
    description: string
    useCase: string
    cpuOverhead: number
    securityLevel: 'medium' | 'medium-high' | 'high' | 'very_high' | 'maximum'
    icon: string
}

export const RECIPE_DEFINITIONS: Record<ZTMRecipeKey, RecipeDefinition> = {
    FULL_STACK: {
        name: 'Full Stack',
        algorithms: ['LFSR', 'Tinkerbell', 'ChaCha20', 'Salsa20', 'Transposition'],
        description: 'Maximum security - all algorithms active',
        useCase: 'RNG manipulation detected, maximum threat level',
        cpuOverhead: 180,
        securityLevel: 'maximum',
        icon: '🛡️'
    },
    CHACHA_HEAVY: {
        name: 'ChaCha Heavy',
        algorithms: ['LFSR', 'Tinkerbell', 'ChaCha20'],
        description: 'ChaCha20 with chaos algorithms',
        useCase: 'Timing attacks detected, need constant-time cipher',
        cpuOverhead: 140,
        securityLevel: 'very_high',
        icon: '⚡'
    },
    SALSA_LIGHT: {
        name: 'Salsa Light',
        algorithms: ['LFSR', 'Salsa20'],
        description: 'Lightweight stream cipher only',
        useCase: 'CPU/memory stress detected, need low-overhead cipher',
        cpuOverhead: 120,
        securityLevel: 'medium-high',
        icon: '💨'
    },
    CHAOS_ONLY: {
        name: 'Chaos Only',
        algorithms: ['LFSR', 'Tinkerbell', 'Transposition'],
        description: 'Baseline fusion - no stream ciphers',
        useCase: 'DoS detected, maintain baseline security',
        cpuOverhead: 100,
        securityLevel: 'high',
        icon: '🌀'
    },
    STREAM_FOCUS: {
        name: 'Stream Focus',
        algorithms: ['ChaCha20', 'Salsa20'],
        description: 'Stream ciphers only - minimal chaos',
        useCase: 'High throughput required with stream cipher protection',
        cpuOverhead: 130,
        securityLevel: 'high',
        icon: '🌊'
    }
}

interface ZTMRecipesPanelProps {
    activeRecipe: ZTMRecipeKey
    onRecipeSwitch: (recipe: ZTMRecipeKey) => void
    isEnabled: boolean
}

export default function ZTMRecipesPanel({
    activeRecipe,
    onRecipeSwitch,
    isEnabled
}: ZTMRecipesPanelProps) {
    const getSecurityColor = (level: string) => {
        switch (level) {
            case 'maximum': return 'text-red-400 bg-red-500/20 border-red-500/50'
            case 'very_high': return 'text-orange-400 bg-orange-500/20 border-orange-500/50'
            case 'high': return 'text-yellow-400 bg-yellow-500/20 border-yellow-500/50'
            case 'medium-high': return 'text-green-400 bg-green-500/20 border-green-500/50'
            default: return 'text-gray-400 bg-gray-500/20 border-gray-500/50'
        }
    }

    return (
        <div className="bg-gray-900 border border-gray-700 rounded-xl p-6">
            <h2 className="text-xl font-bold text-red-400 font-mono mb-4 flex items-center gap-2">
                <span>📋</span> AVAILABLE RECIPES
            </h2>

            <div className="space-y-3">
                {(Object.entries(RECIPE_DEFINITIONS) as [ZTMRecipeKey, RecipeDefinition][]).map(([key, recipe]) => {
                    const isActive = activeRecipe === key

                    return (
                        <motion.button
                            key={key}
                            onClick={() => isEnabled && onRecipeSwitch(key)}
                            disabled={!isEnabled || isActive}
                            className={`w-full text-left p-4 rounded-xl border-2 transition-all duration-300
                ${isActive
                                    ? 'bg-red-500/20 border-red-500 shadow-lg shadow-red-500/20'
                                    : 'bg-gray-800/50 border-gray-700 hover:border-gray-600 hover:bg-gray-800'
                                }
                ${!isEnabled ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'}
              `}
                            whileHover={isEnabled && !isActive ? { scale: 1.01 } : {}}
                            whileTap={isEnabled && !isActive ? { scale: 0.99 } : {}}
                        >
                            <div className="flex items-start justify-between">
                                <div className="flex-1">
                                    <div className="flex items-center gap-2 mb-1">
                                        <span className="text-xl">{recipe.icon}</span>
                                        <span className={`font-mono font-bold ${isActive ? 'text-red-400' : 'text-white'}`}>
                                            {recipe.name}
                                        </span>
                                        {isActive && (
                                            <span className="px-2 py-0.5 text-xs font-mono bg-red-500/30 text-red-300 rounded">
                                                ACTIVE
                                            </span>
                                        )}
                                    </div>

                                    <p className="text-gray-400 text-sm mb-2">{recipe.description}</p>

                                    <div className="flex flex-wrap gap-1 mb-2">
                                        {recipe.algorithms.map((alg, idx) => (
                                            <span
                                                key={idx}
                                                className={`px-2 py-0.5 text-xs font-mono rounded
                          ${isActive
                                                        ? 'bg-green-500/20 text-green-400 border border-green-500/30'
                                                        : 'bg-gray-700 text-gray-300'
                                                    }`}
                                            >
                                                {alg}
                                            </span>
                                        ))}
                                    </div>

                                    <div className="flex items-center gap-3 text-xs">
                                        <span className={`px-2 py-0.5 rounded border ${getSecurityColor(recipe.securityLevel)}`}>
                                            {recipe.securityLevel.toUpperCase()}
                                        </span>
                                        <span className="text-gray-500">
                                            CPU: {recipe.cpuOverhead}%
                                        </span>
                                    </div>
                                </div>
                            </div>

                            {/* Use Case - shown on hover/active */}
                            {isActive && (
                                <motion.div
                                    initial={{ opacity: 0, height: 0 }}
                                    animate={{ opacity: 1, height: 'auto' }}
                                    className="mt-3 pt-3 border-t border-gray-700"
                                >
                                    <p className="text-xs text-gray-500">
                                        <span className="text-yellow-400">💡 When to use:</span> {recipe.useCase}
                                    </p>
                                </motion.div>
                            )}
                        </motion.button>
                    )
                })}
            </div>
        </div>
    )
}
