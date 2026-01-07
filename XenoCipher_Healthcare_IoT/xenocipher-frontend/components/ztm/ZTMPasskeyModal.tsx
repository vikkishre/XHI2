'use client'

import React, { useState, useEffect, useRef } from 'react'
import { AnimatePresence } from 'framer-motion'
import { MotionDiv, MotionInput } from '../../lib/motion'

interface ZTMPasskeyModalProps {
    isOpen: boolean
    onSuccess: () => void
    onCancel: () => void
}

export default function ZTMPasskeyModal({ isOpen, onSuccess, onCancel }: ZTMPasskeyModalProps) {
    const [digits, setDigits] = useState<string[]>(['', '', '', ''])
    const [error, setError] = useState<string | null>(null)
    const [isVerifying, setIsVerifying] = useState(false)
    const inputRefs = useRef<(HTMLInputElement | null)[]>([])

    // Focus first input when modal opens
    useEffect(() => {
        if (isOpen && inputRefs.current[0]) {
            setTimeout(() => inputRefs.current[0]?.focus(), 100)
        }
    }, [isOpen])

    const handleDigitChange = (index: number, value: string) => {
        if (!/^\d*$/.test(value)) return

        const newDigits = [...digits]
        newDigits[index] = value.slice(-1)
        setDigits(newDigits)
        setError(null)

        // Auto-focus next input
        if (value && index < 3) {
            inputRefs.current[index + 1]?.focus()
        }

        // Auto-submit when all digits are entered
        if (newDigits.every(d => d !== '') && value) {
            handleVerify(newDigits)
        }
    }

    const handleKeyDown = (index: number, e: React.KeyboardEvent) => {
        if (e.key === 'Backspace' && !digits[index] && index > 0) {
            inputRefs.current[index - 1]?.focus()
        }
    }

    const handleVerify = async (passDigits: string[]) => {
        const passkey = passDigits.join('')
        setIsVerifying(true)
        setError(null)

        // Simulate verification delay for UX
        await new Promise(resolve => setTimeout(resolve, 500))

        // Default passkey is 1234, configurable via env
        const correctPasskey = process.env.NEXT_PUBLIC_ZTM_PASSKEY || '1234'

        if (passkey === correctPasskey) {
            setIsVerifying(false)
            onSuccess()
        } else {
            setIsVerifying(false)
            setError('Invalid passkey. Please try again.')
            setDigits(['', '', '', ''])
            inputRefs.current[0]?.focus()
        }
    }

    const handlePaste = (e: React.ClipboardEvent) => {
        e.preventDefault()
        const pasted = e.clipboardData.getData('text').replace(/\D/g, '').slice(0, 4)
        if (pasted.length === 4) {
            const newDigits = pasted.split('')
            setDigits(newDigits)
            handleVerify(newDigits)
        }
    }

    if (!isOpen) return null

    return (
        <AnimatePresence mode="wait">
            <MotionDiv
                key="passkey-overlay"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm"
                onClick={onCancel}
            >
                <MotionDiv
                    key="passkey-modal"
                    initial={{ scale: 0.9, opacity: 0 }}
                    animate={{ scale: 1, opacity: 1 }}
                    exit={{ scale: 0.9, opacity: 0 }}
                    transition={{ type: 'spring', damping: 25 }}
                    className="bg-gray-900 border border-red-500/50 rounded-2xl p-8 max-w-md w-full mx-4 shadow-2xl shadow-red-500/20"
                    onClick={(e: React.MouseEvent) => e.stopPropagation()}
                >
                    {/* Header */}
                    <div className="text-center mb-8">
                        <div className="text-5xl mb-4">🔐</div>
                        <h2 className="text-2xl font-bold text-red-500 font-mono mb-2">
                            ZERO TRUST MODE
                        </h2>
                        <p className="text-gray-400 text-sm">
                            Enter 4-digit passkey to activate ZTM
                        </p>
                    </div>

                    {/* Passkey Input */}
                    <div className="flex justify-center gap-4 mb-6" onPaste={handlePaste}>
                        {digits.map((digit, index) => (
                            <input
                                key={`digit-${index}`}
                                ref={el => { inputRefs.current[index] = el }}
                                type="text"
                                inputMode="numeric"
                                maxLength={1}
                                value={digit}
                                onChange={e => handleDigitChange(index, e.target.value)}
                                onKeyDown={e => handleKeyDown(index, e)}
                                disabled={isVerifying}
                                className={`w-16 h-20 text-center text-3xl font-mono font-bold rounded-xl
                  border-2 transition-all duration-200 bg-gray-800
                  ${error
                                        ? 'border-red-500 text-red-400'
                                        : digit
                                            ? 'border-green-500 text-green-400'
                                            : 'border-gray-600 text-white'
                                    }
                  focus:outline-none focus:border-red-400 focus:ring-2 focus:ring-red-500/30
                  disabled:opacity-50`}
                            />
                        ))}
                    </div>

                    {/* Error Message */}
                    <AnimatePresence mode="wait">
                        {error && (
                            <MotionDiv
                                key="error-message"
                                initial={{ opacity: 0, y: -10 }}
                                animate={{ opacity: 1, y: 0 }}
                                exit={{ opacity: 0, y: -10 }}
                                className="text-center mb-6"
                            >
                                <span className="text-red-400 text-sm font-mono">⚠️ {error}</span>
                            </MotionDiv>
                        )}
                    </AnimatePresence>

                    {/* Verifying Spinner */}
                    {isVerifying && (
                        <MotionDiv
                            initial={{ opacity: 0 }}
                            animate={{ opacity: 1 }}
                            className="text-center mb-6"
                        >
                            <div className="inline-block animate-spin text-2xl mb-2">🔄</div>
                            <p className="text-gray-400 text-sm font-mono">Verifying...</p>
                        </MotionDiv>
                    )}

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
                            onClick={() => handleVerify(digits)}
                            disabled={digits.some(d => !d) || isVerifying}
                            className="flex-1 px-6 py-3 bg-red-600 hover:bg-red-500 text-white 
                rounded-xl font-mono text-sm font-bold transition-colors
                disabled:opacity-50 disabled:cursor-not-allowed border border-red-500"
                        >
                            {isVerifying ? 'Verifying...' : 'Activate ZTM'}
                        </button>
                    </div>

                    {/* Help Text */}
                    <p className="text-center text-gray-500 text-xs mt-6">
                        Default passkey: 1234 (configurable via ZTM_PASSKEY env)
                    </p>
                </MotionDiv>
            </MotionDiv>
        </AnimatePresence>
    )
}
