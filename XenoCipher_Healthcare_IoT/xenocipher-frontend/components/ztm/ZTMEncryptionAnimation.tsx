'use client'

import React from 'react'
import { ZTMRecipeKey, RECIPE_DEFINITIONS } from './ZTMRecipesPanel'

interface ZTMEncryptionAnimationProps {
    activeRecipe: ZTMRecipeKey
    isProcessing: boolean
    currentStep?: number
}

const ALGORITHM_VISUALS: Record<string, { icon: string; color: string; label: string }> = {
    LFSR: { icon: '🔄', color: '#22d3ee', label: 'LFSR' },
    Tinkerbell: { icon: '✨', color: '#a855f7', label: 'Chaos' },
    ChaCha20: { icon: '⚡', color: '#eab308', label: 'ChaCha20' },
    Salsa20: { icon: '💨', color: '#22c55e', label: 'Salsa20' },
    Transposition: { icon: '🔀', color: '#ec4899', label: 'Grid' }
}

export default function ZTMEncryptionAnimation({
    activeRecipe,
    isProcessing,
    currentStep = -1
}: ZTMEncryptionAnimationProps) {
    const recipe = RECIPE_DEFINITIONS[activeRecipe]
    const algorithms = recipe.algorithms

    return (
        <div className="bg-gray-900 border border-gray-700 rounded-xl p-6">
            <h2 className="text-xl font-bold text-red-400 font-mono mb-4 flex items-center gap-2">
                <span>🔐</span> ENCRYPTION PIPELINE
                {isProcessing && (
                    <span className="px-2 py-0.5 text-xs bg-green-500/30 text-green-300 rounded animate-pulse">
                        ACTIVE
                    </span>
                )}
            </h2>

            {/* Pipeline Visualization */}
            <div className="flex items-center justify-between gap-2 relative">
                {/* Input */}
                <div
                    className="flex flex-col items-center"
                    style={{
                        transform: isProcessing && currentStep === 0 ? 'scale(1.1)' : 'scale(1)',
                        transition: 'transform 0.3s ease'
                    }}
                >
                    <div className="w-12 h-12 rounded-lg bg-gray-800 border-2 border-green-500 flex items-center justify-center text-xl">
                        📄
                    </div>
                    <span className="text-xs text-gray-400 mt-1">Input</span>
                </div>

                {/* Algorithm Nodes */}
                {algorithms.map((alg, idx) => {
                    const visual = ALGORITHM_VISUALS[alg]
                    const isActive = isProcessing && currentStep === idx + 1
                    const isPast = isProcessing && currentStep > idx + 1

                    return (
                        <React.Fragment key={`${alg}-${idx}`}>
                            {/* Arrow */}
                            <div
                                className="flex-1 h-0.5 bg-gradient-to-r from-gray-600 to-gray-700 relative"
                                style={{ minWidth: '20px' }}
                            >
                                {isProcessing && (isPast || isActive) && (
                                    <div
                                        className="absolute top-0 left-0 h-full"
                                        style={{
                                            background: `linear-gradient(90deg, ${ALGORITHM_VISUALS[algorithms[idx - 1] || 'LFSR']?.color || '#888'}, ${visual.color})`,
                                            width: '100%',
                                            transition: 'width 0.3s ease'
                                        }}
                                    />
                                )}
                            </div>

                            {/* Node */}
                            <div
                                className="flex flex-col items-center relative"
                                style={{
                                    transform: isActive ? 'scale(1.15) translateY(-2px)' : 'scale(1)',
                                    transition: 'transform 0.3s ease'
                                }}
                            >
                                <div
                                    className={`w-12 h-12 rounded-lg flex items-center justify-center text-xl border-2 transition-all duration-300
                    ${isActive
                                            ? 'shadow-lg'
                                            : isPast
                                                ? 'opacity-60'
                                                : 'opacity-40'
                                        }`}
                                    style={{
                                        backgroundColor: `${visual.color}20`,
                                        borderColor: isActive || isPast ? visual.color : '#374151',
                                        boxShadow: isActive ? `0 0 20px ${visual.color}50` : 'none'
                                    }}
                                >
                                    {visual.icon}
                                </div>
                                <span
                                    className="text-[10px] mt-1 font-mono"
                                    style={{ color: isActive || isPast ? visual.color : '#6b7280' }}
                                >
                                    {visual.label}
                                </span>

                                {/* Active indicator */}
                                {isActive && (
                                    <div
                                        className="absolute -top-1 -right-1 w-3 h-3 rounded-full animate-pulse"
                                        style={{ backgroundColor: visual.color }}
                                    />
                                )}
                            </div>
                        </React.Fragment>
                    )
                })}

                {/* Final Arrow */}
                <div
                    className="flex-1 h-0.5 bg-gradient-to-r from-gray-600 to-gray-700 relative"
                    style={{ minWidth: '20px' }}
                >
                    {isProcessing && currentStep >= algorithms.length && (
                        <div
                            className="absolute top-0 left-0 h-full bg-green-500"
                            style={{ width: '100%', transition: 'width 0.3s ease' }}
                        />
                    )}
                </div>

                {/* Output */}
                <div
                    className="flex flex-col items-center"
                    style={{
                        transform: isProcessing && currentStep > algorithms.length ? 'scale(1.1)' : 'scale(1)',
                        transition: 'transform 0.3s ease'
                    }}
                >
                    <div className={`w-12 h-12 rounded-lg bg-gray-800 border-2 flex items-center justify-center text-xl
            ${currentStep > algorithms.length ? 'border-green-500' : 'border-yellow-500'}`}>
                        🔒
                    </div>
                    <span className="text-xs text-gray-400 mt-1">Output</span>
                </div>
            </div>

            {/* Legend */}
            <div className="mt-4 pt-4 border-t border-gray-700">
                <div className="flex flex-wrap gap-3 justify-center text-xs">
                    {algorithms.map((alg, idx) => {
                        const visual = ALGORITHM_VISUALS[alg]
                        return (
                            <div key={`legend-${alg}-${idx}`} className="flex items-center gap-1">
                                <div
                                    className="w-2 h-2 rounded-full"
                                    style={{ backgroundColor: visual.color }}
                                />
                                <span className="text-gray-400">{alg}</span>
                            </div>
                        )
                    })}
                </div>
            </div>

            {/* Recipe Info */}
            <div className="mt-3 text-center text-xs text-gray-500">
                <span className="font-mono">{recipe.name}</span> • {algorithms.length} stages • {recipe.cpuOverhead}% CPU
            </div>
        </div>
    )
}
