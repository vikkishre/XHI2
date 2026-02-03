// components/ZeroTrustMode.tsx
'use client'

import React, { useState, useEffect, useCallback } from 'react'
import { motion } from 'framer-motion'
import { useZeroTrust } from '../context/ZeroTrustContext'
import { useWebSocket } from '../context/WebSocketContext'
import { usePipeline } from '../context/PipelineContext'

// ZTM Component imports
import ZTMPasskeyModal from './ztm/ZTMPasskeyModal'
import ZTMRecipesPanel, { ZTMRecipeKey } from './ztm/ZTMRecipesPanel'
import ZTMActiveRecipeDetails from './ztm/ZTMActiveRecipeDetails'
import ZTMThreatMetricsDashboard from './ztm/ZTMThreatMetricsDashboard'
import ZTMAlertSystem from './ztm/ZTMAlertSystem'
import ZTMKeyNonceStatus from './ztm/ZTMKeyNonceStatus'
import ZTMEventLog from './ztm/ZTMEventLog'
import ZTMExitConfirmModal from './ztm/ZTMExitConfirmModal'
import ZTMESPServerHealthView from './ztm/ZTMESPServerHealthView'
import ZTMEncryptionAnimation from './ztm/ZTMEncryptionAnimation'

// Bonus Components
import ZTMDeveloperPanel from './ztm/ZTMDeveloperPanel'
import ZTMSessionExport from './ztm/ZTMSessionExport'
import ZTMHistoricalMetrics from './ztm/ZTMHistoricalMetrics'

// Utility wrapper for motion components
function createMotionWithClass(Component: any) {
  return React.forwardRef(function MotionWithClass(props: any, ref) {
    const { className, ...rest } = props
    return <Component ref={ref} {...rest} {...(className ? { className } : {})} />
  })
}

const MotionDiv = createMotionWithClass(motion.div)
const MotionButton = createMotionWithClass(motion.button)

export default function ZeroTrustMode() {
  // Context hooks
  const {
    isZeroTrustMode,
    isPasskeyVerified,
    verifyPasskey,
    enableZeroTrust,
    disableZeroTrust,
    activeRecipe,
    switchRecipe,
    lastSwitchReason,
    lastSwitchTime,
    heuristics,
    alerts,
    dismissAlert,
    clearAlerts,
    eventLogs,
    clearEventLogs,
    addEventLog
  } = useZeroTrust()

  const { isConnected, lastMessage } = useWebSocket()
  const { pipelineData } = usePipeline()

  // Local UI state
  const [showPasskeyModal, setShowPasskeyModal] = useState(false)
  const [showExitModal, setShowExitModal] = useState(false)
  const [isActivating, setIsActivating] = useState(false)
  const [animationStep, setAnimationStep] = useState(-1)

  // Key and nonce state from pipeline
  const keyStatus = {
    initialized: !!pipelineData.esp32Data?.masterKey || pipelineData.esp32Connected,
    lastRegen: lastSwitchTime,
    algorithm: `XenoCipher-${activeRecipe}`
  }

  const nonceStatus = {
    current: Math.floor(Math.random() * 10000), // Simulated nonce counter
    refreshed: true,
    reuseWarning: false
  }

  // ESP32 and Server data from pipeline
  const esp32Data = {
    connected: pipelineData.esp32Connected,
    lastSeen: pipelineData.lastUpdated,
    encryptedData: pipelineData.esp32Data?.encryptedPacket || null,
    algorithm: activeRecipe
  }

  const serverData = {
    connected: pipelineData.serverConnected,
    lastSeen: pipelineData.lastUpdated,
    decryptedData: pipelineData.serverData?.decryptedData || null,
    decryptionTime: pipelineData.serverData?.decryptionTime || null
  }

  const healthData = pipelineData.serverData?.healthData

  // Simulate encryption animation progress
  useEffect(() => {
    if (!isZeroTrustMode || pipelineData.currentStep === 'idle') {
      setAnimationStep(-1)
      return
    }

    const animationInterval = setInterval(() => {
      setAnimationStep(prev => {
        const maxSteps = 6 // Input + algorithms + output
        return prev < maxSteps ? prev + 1 : -1
      })
    }, 800)

    return () => clearInterval(animationInterval)
  }, [isZeroTrustMode, pipelineData.currentStep])

  // Handle passkey verification
  const handlePasskeySubmit = async (passkey: string) => {
    const success = await verifyPasskey(passkey)
    if (success) {
      setShowPasskeyModal(false)
      setIsActivating(true)
      enableZeroTrust(passkey)  // Pass the passkey that was just verified
      setTimeout(() => setIsActivating(false), 1500)
    }
    return success
  }

  // Handle ZTM activation
  const handleActivateZTM = () => {
    if (!isPasskeyVerified) {
      setShowPasskeyModal(true)
    } else {
      setIsActivating(true)
      enableZeroTrust()
      setTimeout(() => setIsActivating(false), 1500)
    }
  }

  // Handle ZTM deactivation
  const handleDeactivateZTM = () => {
    setShowExitModal(true)
  }

  const confirmDeactivateZTM = () => {
    setShowExitModal(false)
    disableZeroTrust()
  }

  // Handle recipe switch
  const handleRecipeSwitch = (recipe: ZTMRecipeKey) => {
    if (recipe !== activeRecipe) {
      switchRecipe(recipe, `Manual switch from ${activeRecipe} to ${recipe}`)
    }
  }

  // Export logs
  const handleExportLogs = () => {
    const exportData = {
      exportedAt: new Date().toISOString(),
      mode: 'ZTM',
      recipe: activeRecipe,
      heuristics,
      alerts,
      eventLogs
    }
    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `ztm-session-${Date.now()}.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  // Show passkey gate if not verified and not in ZTM mode
  if (!isZeroTrustMode && !isActivating) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-gray-900 via-black to-red-950 p-8">
        <div className="container mx-auto max-w-4xl">
          {/* Header */}
          <MotionDiv
            className="text-center mb-12"
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
          >
            <div className="text-6xl mb-4">🛡️</div>
            <h1 className="text-4xl font-bold text-red-500 font-mono mb-2">
              ZERO TRUST MODE
            </h1>
            <p className="text-gray-400 text-lg">
              Adaptive encryption with real-time threat response
            </p>
          </MotionDiv>

          {/* Activation Panel */}
          <MotionDiv
            className="bg-gray-900/80 border border-red-500/50 rounded-2xl p-8 shadow-2xl shadow-red-500/10"
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
          >
            <div className="text-center">
              <h2 className="text-2xl font-bold text-white mb-4">
                Enhanced Security Required
              </h2>
              <p className="text-gray-400 mb-6 max-w-lg mx-auto">
                Zero Trust Mode provides adaptive encryption switching based on real-time
                threat detection. Enter your 4-digit passkey to activate.
              </p>

              {/* Features List */}
              <div className="grid grid-cols-2 gap-4 mb-8 text-left max-w-2xl mx-auto">
                <div className="p-3 bg-gray-800/50 rounded-lg">
                  <span className="text-xl mr-2">⚡</span>
                  <span className="text-gray-300 text-sm">5 Adaptive Recipes</span>
                </div>
                <div className="p-3 bg-gray-800/50 rounded-lg">
                  <span className="text-xl mr-2">📊</span>
                  <span className="text-gray-300 text-sm">Real-time Threat Metrics</span>
                </div>
                <div className="p-3 bg-gray-800/50 rounded-lg">
                  <span className="text-xl mr-2">🔐</span>
                  <span className="text-gray-300 text-sm">ChaCha20 + Salsa20</span>
                </div>
                <div className="p-3 bg-gray-800/50 rounded-lg">
                  <span className="text-xl mr-2">🚨</span>
                  <span className="text-gray-300 text-sm">Automatic Response</span>
                </div>
              </div>

              <MotionButton
                className="px-8 py-4 bg-red-600 hover:bg-red-500 text-white rounded-xl 
                  font-mono font-bold text-lg transition-all border border-red-500 
                  shadow-lg shadow-red-500/25 cursor-pointer"
                onClick={handleActivateZTM}
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
              >
                🔐 ENTER PASSKEY TO ACTIVATE
              </MotionButton>

              <p className="text-gray-500 text-xs mt-4">
                Connection: {isConnected ? '🟢 Server Connected' : '🔴 Server Disconnected'}
              </p>
            </div>
          </MotionDiv>

          {/* Info Panel */}
          <MotionDiv
            className="mt-8 p-4 bg-yellow-500/10 border border-yellow-500/30 rounded-lg"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.3 }}
          >
            <p className="text-yellow-400 text-sm text-center">
              💡 Normal Mode alerts are informational only.
              Activate ZTM for automatic encryption adaptation.
            </p>
          </MotionDiv>
        </div>

        {/* Passkey Modal */}
        <ZTMPasskeyModal
          isOpen={showPasskeyModal}
          onSuccess={(passkey: string) => {
            setShowPasskeyModal(false)
            setIsActivating(true)
            enableZeroTrust(passkey)  // Pass the verified passkey to server
            setTimeout(() => setIsActivating(false), 1500)
          }}
          onCancel={() => setShowPasskeyModal(false)}
        />
      </div>
    )
  }

  // Show activating spinner
  if (isActivating) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-gray-900 via-black to-red-950 flex items-center justify-center">
        <MotionDiv
          className="text-center"
          initial={{ opacity: 0, scale: 0.8 }}
          animate={{ opacity: 1, scale: 1 }}
        >
          <div className="text-8xl mb-6 animate-pulse">🛡️</div>
          <h2 className="text-3xl font-bold text-red-500 font-mono mb-2">
            ACTIVATING ZTM
          </h2>
          <p className="text-gray-400">Initializing adaptive encryption...</p>
          <div className="mt-6">
            <div className="w-64 h-2 bg-gray-800 rounded-full overflow-hidden mx-auto">
              <MotionDiv
                className="h-full bg-gradient-to-r from-red-500 to-yellow-500"
                initial={{ width: '0%' }}
                animate={{ width: '100%' }}
                transition={{ duration: 1.5, ease: 'easeOut' }}
              />
            </div>
          </div>
        </MotionDiv>
      </div>
    )
  }

  // Main ZTM Dashboard
  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-black to-red-950 p-4 lg:p-8">
      {/* Header */}
      <div className="container mx-auto max-w-7xl">
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-4">
            <div className="text-4xl">🛡️</div>
            <div>
              <h1 className="text-2xl font-bold text-red-400 font-mono">
                ZERO TRUST MODE
              </h1>
              <p className="text-gray-400 text-sm">
                Recipe: <span className="text-green-400 font-mono">{activeRecipe}</span>
              </p>
            </div>
          </div>

          <div className="flex items-center gap-4">
            <div className={`px-3 py-1 rounded border ${isConnected
              ? 'bg-green-500/20 border-green-500 text-green-400'
              : 'bg-red-500/20 border-red-500 text-red-400'
              }`}>
              {isConnected ? '🟢 Connected' : '🔴 Disconnected'}
            </div>

            <MotionButton
              className="px-4 py-2 bg-yellow-600 hover:bg-yellow-500 text-white rounded-lg 
                font-mono text-sm font-bold transition-all border border-yellow-500 cursor-pointer"
              onClick={handleExportLogs}
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
            >
              📥 Export
            </MotionButton>

            <MotionButton
              className="px-4 py-2 bg-red-600 hover:bg-red-500 text-white rounded-lg 
                font-mono text-sm font-bold transition-all border border-red-500 cursor-pointer"
              onClick={handleDeactivateZTM}
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
            >
              ⚠️ EXIT ZTM
            </MotionButton>
          </div>
        </div>

        {/* Full Width Encryption Pipeline */}
        <div className="mb-6">
          <ZTMEncryptionAnimation
            activeRecipe={activeRecipe}
            isProcessing={pipelineData.currentStep !== 'idle' && pipelineData.currentStep !== 'completed'}
            currentStep={animationStep}
          />
        </div>

        {/* Main Three Column Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Left Column: Recipes, Active Recipe Details, ESP-Server View */}
          <div className="space-y-6">
            <ZTMRecipesPanel
              activeRecipe={activeRecipe}
              onRecipeSwitch={handleRecipeSwitch}
              isEnabled={isZeroTrustMode}
            />
            <ZTMActiveRecipeDetails
              activeRecipe={activeRecipe}
              switchReason={lastSwitchReason || undefined}
              switchedAt={lastSwitchTime || undefined}
            />
          </div>

          {/* Center Column: ESP-Server View, Threat Metrics, Historical Metrics, Session Export */}
          <div className="space-y-6">
            <ZTMESPServerHealthView
              esp32={esp32Data}
              server={serverData}
              healthData={healthData}
            />
            <ZTMThreatMetricsDashboard
              metrics={heuristics}
              isZTMEnabled={isZeroTrustMode}
            />
            <ZTMHistoricalMetrics />
            <ZTMSessionExport />
          </div>

          {/* Right Column: Alerts, Key Status, Event Log, Developer Panel */}
          <div className="space-y-6">
            <ZTMAlertSystem
              alerts={alerts}
              isZTMEnabled={isZeroTrustMode}
              onDismiss={dismissAlert}
              onDismissAll={clearAlerts}
            />
            <ZTMKeyNonceStatus
              keyStatus={keyStatus}
              nonceStatus={nonceStatus}
              isZTMEnabled={isZeroTrustMode}
            />
            <ZTMEventLog
              logs={eventLogs}
              maxHeight="200px"
              onClear={clearEventLogs}
              onExport={handleExportLogs}
            />
            <ZTMDeveloperPanel />
          </div>
        </div>
      </div>

      {/* Exit Confirmation Modal */}
      <ZTMExitConfirmModal
        isOpen={showExitModal}
        onConfirm={confirmDeactivateZTM}
        onCancel={() => setShowExitModal(false)}
        currentRecipe={activeRecipe}
      />
    </div>
  )
}
