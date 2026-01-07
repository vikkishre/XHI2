'use client'

import React from 'react'
import { motion, AnimatePresence } from 'framer-motion'

interface ZTMExitConfirmModalProps {
    isOpen: boolean
    onConfirm: () => void
    onCancel: () => void
    currentRecipe: string
}

export default function ZTMExitConfirmModal({
    isOpen,
    onConfirm,
    onCancel,
    currentRecipe
}: ZTMExitConfirmModalProps) {
    if (!isOpen) return null

    return (
        <AnimatePresence>
            <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm"
                onClick={onCancel}
            >
                <motion.div
                    initial={{ scale: 0.9, opacity: 0 }}
                    animate={{ scale: 1, opacity: 1 }}
                    exit={{ scale: 0.9, opacity: 0 }}
                    transition={{ type: 'spring', damping: 25 }}
                    className="bg-gray-900 border border-yellow-500/50 rounded-2xl p-8 max-w-lg w-full mx-4 shadow-2xl shadow-yellow-500/10"
                    onClick={e => e.stopPropagation()}
                >
                    {/* Warning Icon */}
                    <div className="text-center mb-6">
                        <div className="text-6xl mb-4">⚠️</div>
                        <h2 className="text-2xl font-bold text-yellow-400 font-mono mb-2">
                            EXIT ZERO TRUST MODE?
                        </h2>
                    </div>

                    {/* Consequences List */}
                    <div className="bg-gray-800/50 border border-gray-700 rounded-lg p-4 mb-6">
                        <h3 className="text-sm font-mono text-gray-400 mb-3">This action will:</h3>
                        <ul className="space-y-2 text-sm">
                            <li className="flex items-start gap-2">
                                <span className="text-red-400">✗</span>
                                <span className="text-gray-300">Disable adaptive encryption switching</span>
                            </li>
                            <li className="flex items-start gap-2">
                                <span className="text-red-400">✗</span>
                                <span className="text-gray-300">
                                    Revert from <span className="font-mono text-yellow-400">{currentRecipe}</span> to Normal Mode
                                </span>
                            </li>
                            <li className="flex items-start gap-2">
                                <span className="text-red-400">✗</span>
                                <span className="text-gray-300">Stop all ZTM encryption algorithms (ChaCha20, Salsa20)</span>
                            </li>
                            <li className="flex items-start gap-2">
                                <span className="text-red-400">✗</span>
                                <span className="text-gray-300">Reset threat detection heuristics counters</span>
                            </li>
                            <li className="flex items-start gap-2">
                                <span className="text-green-400">✓</span>
                                <span className="text-gray-300">Resume Normal Mode encryption (LFSR + Tinkerbell + Transposition)</span>
                            </li>
                        </ul>
                    </div>

                    {/* Warning Note */}
                    <div className="mb-6 p-3 bg-yellow-500/10 border border-yellow-500/30 rounded-lg">
                        <p className="text-yellow-400 text-xs font-mono">
                            ⚠️ If active threats are detected, leaving ZTM may reduce security posture
                        </p>
                    </div>

                    {/* Actions */}
                    <div className="flex gap-4">
                        <button
                            onClick={onCancel}
                            className="flex-1 px-6 py-3 bg-gray-800 hover:bg-gray-700 text-gray-300 
                rounded-xl font-mono text-sm transition-colors border border-gray-700"
                        >
                            Cancel
                        </button>
                        <button
                            onClick={onConfirm}
                            className="flex-1 px-6 py-3 bg-red-600 hover:bg-red-500 text-white 
                rounded-xl font-mono text-sm font-bold transition-colors border border-red-500"
                        >
                            ⚠️ Exit ZTM
                        </button>
                    </div>
                </motion.div>
            </motion.div>
        </AnimatePresence>
    )
}
