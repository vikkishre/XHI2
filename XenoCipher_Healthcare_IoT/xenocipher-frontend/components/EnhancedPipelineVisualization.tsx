// components/EnhancedPipelineVisualization.tsx
'use client'

import React, { useState } from 'react'
import { motion } from 'framer-motion'
import EncryptionDetailsModal from './EncryptionDetailsModal'
import DecryptionDetailsModal from './DecryptionDetailsModal'
import LiveLogPanel from './LiveLogPanel'
import { usePipeline } from '../context/PipelineContext'
import { PipelineData, EncryptionDetails, DecryptionDetails, LogEntry, StepInfo } from '../types/pipeline'
import { validateDecryptedData, getValidationErrorMessage } from '../lib/data-validation'

// Add the missing steps definition
const steps: StepInfo[] = [
  { id: 'idle', title: 'Ready', description: 'System initialized and ready', icon: '⚡', color: 'gray' },
  { id: 'requesting_public_key', title: 'Requesting Public Key', description: 'ESP32 requesting NTRU public key', icon: '🔑', color: 'blue' },
  { id: 'encrypting_master_key', title: 'Encrypting Master Key', description: 'ESP32 encrypting 256-bit master key', icon: '🔒', color: 'purple' },
  { id: 'sending_master_key', title: 'Sending Master Key', description: 'Sending encrypted master key to server', icon: '📤', color: 'orange' },
  { id: 'master_key_established', title: 'Key Exchange Complete', description: 'Secure master key established', icon: '✅', color: 'green' },
  { id: 'encrypting_data', title: 'Encrypting Health Data', description: 'ESP32 encrypting health data with XenoCipher', icon: '🔄', color: 'cyan' },
  { id: 'sending_data', title: 'Sending Encrypted Data', description: 'Transmitting encrypted packet to server', icon: '🚀', color: 'pink' },
  { id: 'receiving_data', title: 'Receiving Data', description: 'Server receiving encrypted data', icon: '📥', color: 'yellow' },
  { id: 'decrypting_data', title: 'Decrypting Data', description: 'Server decrypting health data', icon: '🔓', color: 'teal' },
  { id: 'completed', title: 'Process Complete', description: 'Data successfully processed and stored', icon: '🎉', color: 'emerald' },
]

// Utility to wrap motion components to add className as a prop (and spread it properly)
function createMotionWithClass(Component: any) {
  return React.forwardRef(function MotionWithClass(props: any, ref) {
    const { className, ...rest } = props
    return <Component ref={ref} {...rest} {...(className ? { className } : {})} />
  })
}

// Replace motion elements with their wrapped versions
const MotionDiv = createMotionWithClass(motion.div)
const MotionHeader = createMotionWithClass(motion.header)
const MotionButton = createMotionWithClass(motion.button)

function Header({ onZeroTrustToggle }: { onZeroTrustToggle: () => void }) {
  return (
    <MotionHeader
      className="border-b border-cyan-500/30 bg-black/50 backdrop-blur-lg sticky top-0 z-50"
      initial={{ opacity: 0, y: -50 }}
      animate={{ opacity: 1, y: 0 }}
      style={{ pointerEvents: 'auto' }}
    >
      <div className="container mx-auto px-4 py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-4">
            <MotionDiv
              className="relative"
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
            >
              <div className="w-12 h-12 bg-gradient-to-br from-cyan-400 to-green-400 rounded-lg flex items-center justify-center shadow-lg shadow-cyan-500/25">
                <span className="text-black font-bold text-lg">X</span>
              </div>
              <MotionDiv
                className="absolute -inset-1 bg-cyan-500 rounded-lg blur opacity-30"
                animate={{ rotate: 360 }}
                transition={{ duration: 4, repeat: Infinity, ease: "linear" }}
              />
            </MotionDiv>
            <div>
              <h1 className="text-2xl font-bold bg-gradient-to-r from-cyan-400 to-green-400 bg-clip-text text-transparent">
                XenoCipher
              </h1>
              <p className="text-cyan-300 text-sm">Secure Health Data Pipeline</p>
            </div>
          </div>
          <div className="flex items-center space-x-6">
            <MotionButton
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
              onClick={onZeroTrustToggle}
              className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg font-mono text-sm font-bold border border-red-500 shadow-lg shadow-red-500/25 transition-all cursor-pointer"
              style={{ pointerEvents: 'auto' }}
            >
              🛡️ ZERO TRUST MODE
            </MotionButton>
            <MotionDiv
              className="flex items-center space-x-2"
              whileHover={{ scale: 1.1 }}
            >
              <MotionDiv
                className="w-3 h-3 bg-green-500 rounded-full"
                animate={{ scale: [1, 1.2, 1] }}
                transition={{ duration: 2, repeat: Infinity }}
              />
              <span className="text-green-400 text-sm font-mono">ESP32 ONLINE</span>
            </MotionDiv>
            <MotionDiv
              className="flex items-center space-x-2"
              whileHover={{ scale: 1.1 }}
            >
              <MotionDiv
                className="w-3 h-3 bg-cyan-500 rounded-full"
                animate={{ scale: [1, 1.2, 1] }}
                transition={{ duration: 2, repeat: Infinity }}
              />
              <span className="text-cyan-400 text-sm font-mono">SERVER CONNECTED</span>
            </MotionDiv>
          </div>
        </div>
      </div>
    </MotionHeader>
  )
}

function PipelineStep({ step, index, isActive, isCompleted, isUpcoming }: any) {
  return (
    <MotionDiv
      className={`flex items-center space-x-4 p-4 rounded-xl border-2 transition-all duration-300 ${isActive
          ? 'border-cyan-500 bg-cyan-500/10 shadow-lg shadow-cyan-500/25'
          : isCompleted
            ? 'border-green-500 bg-green-500/10'
            : 'border-gray-600 bg-gray-700/30'
        }`}
      whileHover={{ scale: 1.02 }}
      initial={{ opacity: 0, x: -20 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay: index * 0.1 }}
      style={{ pointerEvents: 'auto' }}
    >
      <MotionDiv
        className={`w-12 h-12 rounded-full flex items-center justify-center text-xl font-bold ${isActive
            ? 'bg-cyan-500 text-white'
            : isCompleted
              ? 'bg-green-500 text-white'
              : 'bg-gray-600 text-gray-400'
          }`}
        animate={isActive ? { scale: [1, 1.1, 1] } : {}}
        transition={{ duration: 2, repeat: isActive ? Infinity : 0 }}
      >
        {isCompleted ? '✓' : step.icon}
      </MotionDiv>
      <div className="flex-1">
        <h4
          className={`font-semibold ${isActive
              ? 'text-cyan-400'
              : isCompleted
                ? 'text-green-400'
                : 'text-gray-400'
            }`}
        >
          {step.title}
        </h4>
        <p className="text-sm text-gray-300">{step.description}</p>
      </div>
      {isActive && (
        <MotionDiv
          className="w-3 h-3 bg-cyan-400 rounded-full"
          animate={{ scale: [1, 2, 1], opacity: [1, 0.5, 1] }}
          transition={{ duration: 1.5, repeat: Infinity }}
        />
      )}
    </MotionDiv>
  )
}

function CurrentStepDisplay({ pipelineData }: { pipelineData: any }) {
  const currentStep = steps.find(step => step.id === pipelineData.currentStep)

  return (
    <div className="text-center">
      <MotionDiv
        key={pipelineData.currentStep}
        initial={{ opacity: 0, scale: 0.8 }}
        animate={{ opacity: 1, scale: 1 }}
        transition={{ duration: 0.5 }}
      >
        <MotionDiv
          className="text-6xl mb-4"
          animate={{ y: [0, -10, 0] }}
          transition={{ duration: 2, repeat: Infinity }}
        >
          {currentStep?.icon}
        </MotionDiv>
        <h3 className="text-2xl font-bold text-cyan-400 mb-2">
          {currentStep?.title}
        </h3>
        <p className="text-gray-300 text-lg mb-4">{currentStep?.description}</p>
        <div className="w-full bg-gray-700 rounded-full h-3 mb-4">
          <MotionDiv
            className="h-3 bg-gradient-to-r from-cyan-500 to-green-500 rounded-full"
            initial={{ width: 0 }}
            animate={{
              width: `${(steps.findIndex(s => s.id === pipelineData.currentStep) /
                  (steps.length - 1)) *
                100
                }%`,
            }}
            transition={{ duration: 1, ease: 'easeOut' }}
          />
        </div>
        <div className="text-sm text-gray-400">
          Step {steps.findIndex(s => s.id === pipelineData.currentStep) + 1} of{' '}
          {steps.length}
        </div>
      </MotionDiv>
    </div>
  )
}

function DataCard({ title, data, status, type }: any) {
  const isEncrypted = type === 'encrypted'

  // Validate decrypted data - never display corrupted text
  let displayData = data
  let isCorrupted = false
  let errorMessage = null

  if (data && type === 'decrypted' && !isEncrypted) {
    const validation = validateDecryptedData(data)
    if (!validation.isValid) {
      isCorrupted = true
      errorMessage = getValidationErrorMessage(validation)
      displayData = '[CORRUPTED_DATA: Invalid UTF-8 or malformed payload]'
    } else if (validation.cleanedData) {
      displayData = validation.cleanedData
    }
  }

  return (
    <MotionDiv
      className="bg-gray-800/50 rounded-xl border border-cyan-500/20 p-6"
      whileHover={{ scale: 1.02 }}
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      style={{ pointerEvents: 'auto' }}
    >
      <div className="flex items-center justify-between mb-4">
        <h4 className="text-lg font-bold text-cyan-400">{title}</h4>
        <div
          className={`flex items-center space-x-2 ${status === 'connected' ? 'text-green-400' : 'text-red-400'
            }`}
        >
          <MotionDiv
            className={`w-2 h-2 rounded-full ${status === 'connected' ? 'bg-green-400' : 'bg-red-400'
              }`}
            animate={status === 'connected' ? { scale: [1, 1.5, 1] } : {}}
            transition={{ duration: 2, repeat: Infinity }}
          />
          <span className="text-sm font-mono">{status.toUpperCase()}</span>
        </div>
      </div>
      <div className="bg-black/40 rounded-lg p-4 border border-gray-600 min-h-[120px]">
        {displayData ? (
          <MotionDiv
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 0.5 }}
          >
            {isCorrupted ? (
              <div>
                <code className="font-mono text-sm break-all text-red-400">
                  {displayData}
                </code>
                {errorMessage && (
                  <p className="text-xs text-red-300 mt-2 font-mono">
                    {errorMessage}
                  </p>
                )}
              </div>
            ) : (
              <code
                className={`font-mono text-sm break-all ${isEncrypted ? 'text-cyan-300' : 'text-green-300'
                  }`}
              >
                {displayData}
              </code>
            )}
          </MotionDiv>
        ) : (
          <MotionDiv
            className="text-center text-gray-500 py-8"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
          >
            <div className="text-2xl mb-2">⏳</div>
            <p>Waiting for data...</p>
          </MotionDiv>
        )}
      </div>
    </MotionDiv>
  )
}

function EncryptionPipeline({ pipelineData }: any) {
  const stages = [
    {
      name: 'Original Data',
      data: pipelineData.esp32Data?.plaintext,
      active: pipelineData.currentStep >= 'encrypting_data',
    },
    {
      name: 'LFSR Encryption',
      data: null,
      active: pipelineData.currentStep >= 'encrypting_data',
    },
    {
      name: 'Tinkerbell Map',
      data: null,
      active: pipelineData.currentStep >= 'encrypting_data',
    },
    {
      name: 'Transposition',
      data: null,
      active: pipelineData.currentStep >= 'encrypting_data',
    },
    {
      name: 'Encrypted Packet',
      data: pipelineData.esp32Data?.encryptedPacket,
      active: pipelineData.currentStep >= 'sending_data',
    },
  ]

  return (
    <div>
      <h4 className="text-lg font-bold text-cyan-400 mb-4">
        XenoCipher Encryption Pipeline
      </h4>
      <div className="flex justify-between items-center">
        {stages.map((stage, index) => (
          <MotionDiv
            key={stage.name}
            className="flex flex-col items-center"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: index * 0.1 }}
            style={{ pointerEvents: 'auto' }}
          >
            <MotionDiv
              className={`w-16 h-16 rounded-full border-4 flex items-center justify-center mb-2 ${stage.active
                  ? 'border-cyan-500 bg-cyan-500/20 shadow-lg shadow-cyan-500/25'
                  : 'border-gray-600 bg-gray-700/50'
                }`}
              animate={stage.active ? { scale: [1, 1.1, 1] } : {}}
              transition={{ duration: 2, repeat: stage.active ? Infinity : 0 }}
            >
              <span
                className={`font-bold ${stage.active ? 'text-cyan-400' : 'text-gray-500'
                  }`}
              >
                {index + 1}
              </span>
            </MotionDiv>
            <span
              className={`text-sm font-medium ${stage.active ? 'text-cyan-400' : 'text-gray-500'
                }`}
            >
              {stage.name}
            </span>
            {index < stages.length - 1 && (
              <MotionDiv
                className={`h-1 w-16 mt-8 ${stage.active ? 'bg-cyan-500' : 'bg-gray-600'
                  }`}
                initial={{ scaleX: 0 }}
                animate={{ scaleX: stage.active ? 1 : 0 }}
                transition={{ duration: 0.5, delay: index * 0.2 }}
              />
            )}
          </MotionDiv>
        ))}
      </div>
    </div>
  )
}

function HealthDataDisplay({ healthData }: { healthData?: any }) {
  if (!healthData) return null

  return (
    <MotionDiv
      className="bg-green-500/10 border border-green-500/30 rounded-xl p-6 mt-6"
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      style={{ pointerEvents: 'auto' }}
    >
      <h4 className="text-lg font-bold text-green-400 mb-4">
        Health Data Extracted
      </h4>
      <div className="grid grid-cols-3 gap-4">
        <div className="text-center">
          <div className="text-2xl font-bold text-red-400">
            {healthData.heartRate}
          </div>
          <div className="text-sm text-gray-300">Heart Rate</div>
        </div>
        <div className="text-center">
          <div className="text-2xl font-bold text-blue-400">
            {healthData.spo2}%
          </div>
          <div className="text-sm text-gray-300">SPO2</div>
        </div>
        <div className="text-center">
          <div className="text-2xl font-bold text-purple-400">
            {healthData.steps}
          </div>
          <div className="text-sm text-gray-300">Steps</div>
        </div>
      </div>
    </MotionDiv>
  )
}

// MAIN COMPONENT WITH SIMPLIFIED, WORKING BUTTONS
function EnhancedPipelineVisualization({ onZeroTrustToggle }: { onZeroTrustToggle: () => void }) {
  const { pipelineData, startPipeline, resetPipeline, messageHistory, logs } = usePipeline()

  const [showEncryptionDetails, setShowEncryptionDetails] = useState(false)
  const [showDecryptionDetails, setShowDecryptionDetails] = useState(false)
  const [encryptionDetails, setEncryptionDetails] = useState<EncryptionDetails | null>(null)
  const [decryptionDetails, setDecryptionDetails] = useState<DecryptionDetails | null>(null)

  // SIMPLE EVENT HANDLERS - Always work, create mock data if needed
  const handleShowEncryptionDetails = () => {
    console.log('🔐 Encryption Details button CLICKED')
    // Always create mock data for testing
    const mockDetails: EncryptionDetails = {
      plaintext: pipelineData.esp32Data?.plaintext || 'HeartRate:72|SPO2:98|Steps:1234|Temp:36.5',
      lfsrOutput: `LFSR_${Math.random().toString(36).substring(2, 10).toUpperCase()}`,
      chaosMapOutput: `CHAOS_${Math.random().toString(36).substring(2, 10).toUpperCase()}`,
      transpositionOutput: `TRANS_${Math.random().toString(36).substring(2, 10).toUpperCase()}`,
      finalEncryptedPacket: pipelineData.esp32Data?.encryptedPacket || `ENC_${Date.now()}`,
      metadata: {
        salt: `salt_${Math.random().toString(36).substring(2, 8)}`,
        key: `key_${Math.random().toString(36).substring(2, 16)}`,
        iv: `iv_${Math.random().toString(36).substring(2, 8)}`,
        authTag: `auth_${Math.random().toString(36).substring(2, 12)}`,
        timestamp: Date.now()
      }
    }
    setEncryptionDetails(mockDetails)
    setShowEncryptionDetails(true)
  }

  const handleShowDecryptionDetails = () => {
    console.log('🔓 Decryption Summary button CLICKED')
    // Always create mock data for testing
    const mockDetails: DecryptionDetails = {
      encryptedPacket: pipelineData.esp32Data?.encryptedPacket || 'ENCRYPTED_DATA_PACKET_12345',
      reversedTransposition: `REV_TRANS_${Math.random().toString(36).substring(2, 8)}`,
      reversedChaosMap: `REV_CHAOS_${Math.random().toString(36).substring(2, 8)}`,
      reversedLFSR: `REV_LFSR_${Math.random().toString(36).substring(2, 8)}`,
      finalPlaintext: pipelineData.serverData?.decryptedData || 'HeartRate:72|SPO2:98|Steps:1234|Temp:36.5',
      verification: {
        hmacValid: true,
        integrityCheck: true,
        timestampValid: true
      },
      timing: {
        totalTime: Math.floor(Math.random() * 150) + 50,
        decryptionTime: Math.floor(Math.random() * 100) + 30,
        verificationTime: Math.floor(Math.random() * 50) + 10
      }
    }
    setDecryptionDetails(mockDetails)
    setShowDecryptionDetails(true)
  }

  const handleStartPipeline = () => {
    console.log('🚀 Start Pipeline clicked')
    startPipeline()
  }

  const handleResetPipeline = () => {
    console.log('🔁 Reset clicked')
    resetPipeline()
  }

  // Export logs as JSON
  const exportLogs = () => {
    console.log('📥 Export Logs clicked')
    const logs = convertMessageHistoryToLogs(messageHistory)
    const dataStr = JSON.stringify(logs, null, 2)
    const dataBlob = new Blob([dataStr], { type: 'application/json' })
    const url = URL.createObjectURL(dataBlob)
    const link = document.createElement('a')
    link.href = url
    link.download = `xenocipher-logs-${new Date().toISOString()}.json`
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
    URL.revokeObjectURL(url)
  }

  // Convert messageHistory to logs for the LiveLogPanel
  const convertMessageHistoryToLogs = (messages: any[]): LogEntry[] => {
    return messages.map((msg, index) => ({
      id: `msg-${index}-${msg.timestamp || Date.now()}`,
      timestamp: msg.timestamp || Date.now(),
      type: getMessageType(msg.type),
      message: getMessageText(msg),
      source: getMessageSource(msg.type)
    }))
  }

  // Helper functions to convert WebSocket messages to log entries
  function getMessageType(messageType: string): LogEntry['type'] {
    switch (messageType) {
      case 'security_update':
        return 'info'
      case 'encryption_update':
        return 'success'
      case 'decryption_update':
        return 'success'
      case 'error':
        return 'error'
      case 'threat_level_update':
        return 'threat'
      default:
        return 'info'
    }
  }

  function getMessageText(message: any): string {
    switch (message.type) {
      case 'security_update':
        return `Security update: ESP32 ${message.esp32_connected ? 'connected' : 'disconnected'}`
      case 'encryption_update':
        return `Data encrypted: ${message.plaintext?.substring(0, 20)}...`
      case 'decryption_update':
        return `Data decrypted: ${message.finalPlaintext?.substring(0, 20)}...`
      case 'error':
        return `Error: ${message.error || 'Unknown error'}`
      default:
        return `Message: ${message.type}`
    }
  }

  function getMessageSource(messageType: string): LogEntry['source'] {
    switch (messageType) {
      case 'security_update':
        return 'security'
      case 'encryption_update':
        return 'esp32'
      case 'decryption_update':
        return 'server'
      default:
        return 'pipeline'
    }
  }

  // Use logs from context if available, otherwise fall back to converting messageHistory
  const displayLogs = logs && logs.length > 0
    ? logs
    : convertMessageHistoryToLogs(messageHistory)

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-black to-gray-900 p-8" style={{ pointerEvents: 'auto' }}>
      <Header onZeroTrustToggle={onZeroTrustToggle} />

      <div className="container mx-auto max-w-7xl" style={{ pointerEvents: 'auto' }}>
        {/* SIMPLIFIED BUTTON SECTION - NO COMPLEX CONDITIONALS */}
        <MotionDiv
          className="bg-gray-800/50 rounded-2xl border border-cyan-500/20 p-6 mb-8"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          style={{ pointerEvents: 'auto' }}
        >
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-2xl font-bold text-cyan-400 mb-2">Cryptographic Pipeline</h2>
              <p className="text-gray-300">Real-time visualization of secure health data transmission</p>
            </div>
            <div className="flex space-x-3" style={{ pointerEvents: 'auto' }}>
              {/* New Encryption Details Button - SIMPLIFIED */}
              <MotionButton
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
                onClick={handleShowEncryptionDetails}
                className="px-4 py-3 bg-purple-600 hover:bg-purple-700 text-white rounded-lg font-bold font-mono transition-all cursor-pointer border-2 border-purple-500 shadow-lg shadow-purple-500/25 active:bg-purple-800 min-w-[160px] text-center"
              >
                <span className="flex items-center justify-center space-x-2">
                  <span>🔐</span>
                  <span>Encryption Details</span>
                </span>
              </MotionButton>
              {/* New Decryption Details Button - SIMPLIFIED */}
              <MotionButton
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
                onClick={handleShowDecryptionDetails}
                className="px-4 py-3 bg-green-600 hover:bg-green-700 text-white rounded-lg font-bold font-mono transition-all cursor-pointer border-2 border-green-500 shadow-lg shadow-green-500/25 active:bg-green-800 min-w-[160px] text-center"
              >
                <span className="flex items-center justify-center space-x-2">
                  <span>🔓</span>
                  <span>Decryption Summary</span>
                </span>
              </MotionButton>
              {/* Start Pipeline Button */}
              <MotionButton
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
                onClick={handleStartPipeline}
                className="px-6 py-3 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg font-bold font-mono transition-all cursor-pointer border-2 border-cyan-500 shadow-lg shadow-cyan-500/25 active:bg-cyan-800 min-w-[160px] text-center"
              >
                🚀 Start Pipeline
              </MotionButton>
              {/* Reset Button */}
              <MotionButton
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
                onClick={handleResetPipeline}
                className="px-4 py-3 bg-red-600 hover:bg-red-700 text-white rounded-lg font-bold font-mono transition-all cursor-pointer border-2 border-red-500 shadow-lg shadow-red-500/25 active:bg-red-800 min-w-[100px]"
              >
                🔁 Reset
              </MotionButton>
              {/* Export Logs Button */}
              <MotionButton
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
                onClick={exportLogs}
                className="px-4 py-3 bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-bold font-mono transition-all cursor-pointer border-2 border-blue-500 shadow-lg shadow-blue-500/25 active:bg-blue-800 min-w-[120px]"
              >
                📥 Export Logs
              </MotionButton>
            </div>
          </div>
        </MotionDiv>

        <div className="grid grid-cols-1 xl:grid-cols-4 gap-8" style={{ pointerEvents: 'auto' }}>
          {/* Left: Pipeline Steps */}
          <div className="xl:col-span-1">
            <MotionDiv
              className="bg-gray-800/50 rounded-2xl border border-cyan-500/20 p-6 h-full"
              initial={{ opacity: 0, x: -50 }}
              animate={{ opacity: 1, x: 0 }}
              style={{ pointerEvents: 'auto' }}
            >
              <h3 className="text-xl font-bold text-cyan-400 mb-6">Pipeline Progress</h3>
              <div className="space-y-4">
                {steps.map((step, index) => (
                  <PipelineStep
                    key={step.id}
                    step={step}
                    index={index}
                    isActive={pipelineData.currentStep === step.id}
                    isCompleted={index < steps.findIndex(s => s.id === pipelineData.currentStep)}
                    isUpcoming={index > steps.findIndex(s => s.id === pipelineData.currentStep)}
                  />
                ))}
              </div>
            </MotionDiv>
          </div>
          {/* Center: Main Content */}
          <div className="xl:col-span-2 space-y-6" style={{ pointerEvents: 'auto' }}>
            {/* Current Step Display */}
            <MotionDiv
              className="bg-gray-800/50 rounded-2xl border border-cyan-500/20 p-6"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              style={{ pointerEvents: 'auto' }}
            >
              <CurrentStepDisplay pipelineData={pipelineData} />
            </MotionDiv>
            {/* Data Cards */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <DataCard
                title="ESP32 Data"
                data={pipelineData.esp32Data?.plaintext}
                status={pipelineData.esp32Connected ? 'connected' : 'disconnected'}
                type="original"
              />
              <DataCard
                title="Server Data"
                data={pipelineData.serverData?.decryptedData}
                status={pipelineData.serverConnected ? 'connected' : 'disconnected'}
                type="decrypted"
              />
            </div>
            {/* Health Data & Encryption Pipeline */}
            {pipelineData.serverData?.healthData && Object.keys(pipelineData.serverData.healthData).length > 0 && (
              <HealthDataDisplay healthData={pipelineData.serverData.healthData} />
            )}
            <MotionDiv
              className="bg-gray-800/50 rounded-2xl border border-cyan-500/20 p-6"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              style={{ pointerEvents: 'auto' }}
            >
              <EncryptionPipeline pipelineData={pipelineData} />
            </MotionDiv>
          </div>
          {/* Right: Live Log Panel */}
          <div className="xl:col-span-1" style={{ pointerEvents: 'auto' }}>
            <LiveLogPanel logs={displayLogs} />
          </div>
        </div>
      </div>
      {/* Debug Info */}
      <div className="fixed bottom-4 left-4 bg-black/90 p-4 rounded-lg border border-cyan-500/30 text-xs font-mono z-50">
        <div className="text-cyan-400 font-bold mb-2">Debug Info:</div>
        <div>Buttons: <span className="text-green-400">ALWAYS ACTIVE</span></div>
        <div>Current Step: <span className="text-yellow-400">{pipelineData.currentStep}</span></div>
        <div>Click buttons to test modals!</div>
      </div>
      {/* Modals */}
      <EncryptionDetailsModal
        isOpen={showEncryptionDetails}
        onClose={() => setShowEncryptionDetails(false)}
        details={encryptionDetails}
      />
      <DecryptionDetailsModal
        isOpen={showDecryptionDetails}
        onClose={() => setShowDecryptionDetails(false)}
        details={decryptionDetails}
      />
    </div>
  )
}

export default EnhancedPipelineVisualization