// context/ZeroTrustContext.tsx
'use client'

import React, { createContext, useContext, useState, useCallback, useEffect, useRef, ReactNode } from 'react'
import { useWebSocket } from './WebSocketContext'
import { checkThresholds, canTriggerAlert, type HeuristicMetrics as ThresholdMetrics } from '../lib/heuristics-thresholds'
import type { ZTMRecipeKey } from '../components/ztm/ZTMRecipesPanel'
import type { HeuristicMetrics } from '../components/ztm/ZTMThreatMetricsDashboard'
import type { ThreatAlert } from '../components/ztm/ZTMAlertSystem'
import type { LogEntry } from '../components/ztm/ZTMEventLog'

export type ThreatLevel = 'green' | 'yellow' | 'red'

interface ZeroTrustContextType {
  // Core state
  isZeroTrustMode: boolean
  isPasskeyVerified: boolean

  // Actions
  verifyPasskey: (passkey: string) => Promise<boolean>
  enableZeroTrust: () => void
  disableZeroTrust: () => void

  // Recipe management
  activeRecipe: ZTMRecipeKey
  switchRecipe: (recipe: ZTMRecipeKey, reason?: string) => void
  lastSwitchReason: string | null
  lastSwitchTime: number | null

  // Heuristics & Metrics
  heuristics: HeuristicMetrics
  updateHeuristics: (metrics: Partial<HeuristicMetrics>) => void

  // Alerts
  alerts: ThreatAlert[]
  addAlert: (alert: Omit<ThreatAlert, 'id' | 'timestamp'>) => void
  dismissAlert: (id: string) => void
  clearAlerts: () => void

  // Event Log
  eventLogs: LogEntry[]
  addEventLog: (entry: Omit<LogEntry, 'id' | 'timestamp'>) => void
  clearEventLogs: () => void

  // Legacy data object
  zeroTrustData: {
    sessionKey?: string
    ephemeralIdentity?: string
    threatLevel: ThreatLevel
  }
}

const ZeroTrustContext = createContext<ZeroTrustContextType | undefined>(undefined)

interface ZeroTrustProviderProps {
  children: ReactNode
}

// Default heuristics matching heuristics.json baseline
const DEFAULT_HEURISTICS: HeuristicMetrics = {
  latencyMs: 48.5,
  entropyAfter: 7.8,
  memoryPercent: 0.204,
  cpuPercent: 0.0,
  hmacFailures: 0,
  decryptFailures: 0,
  replayAttempts: 0,
  malformedPackets: 0,
  timingAnomalies: 0
}

export function ZeroTrustProvider({ children }: ZeroTrustProviderProps) {
  const { lastMessage, sendMessage } = useWebSocket()

  // Core state
  const [isZeroTrustMode, setIsZeroTrustMode] = useState(false)
  const [isPasskeyVerified, setIsPasskeyVerified] = useState(false)

  // Recipe state
  const [activeRecipe, setActiveRecipe] = useState<ZTMRecipeKey>('CHAOS_ONLY')
  const [lastSwitchReason, setLastSwitchReason] = useState<string | null>(null)
  const [lastSwitchTime, setLastSwitchTime] = useState<number | null>(null)

  // Heuristics state
  const [heuristics, setHeuristics] = useState<HeuristicMetrics>(DEFAULT_HEURISTICS)

  // Alerts state
  const [alerts, setAlerts] = useState<ThreatAlert[]>([])

  // Event logs state
  const [eventLogs, setEventLogs] = useState<LogEntry[]>([])

  // Legacy data
  const [zeroTrustData, setZeroTrustData] = useState<{
    sessionKey?: string
    ephemeralIdentity?: string
    threatLevel: ThreatLevel
  }>({ threatLevel: 'green' })

  // Passkey verification
  const verifyPasskey = useCallback(async (passkey: string): Promise<boolean> => {
    const correctPasskey = process.env.NEXT_PUBLIC_ZTM_PASSKEY || '1234'

    if (passkey === correctPasskey) {
      setIsPasskeyVerified(true)
      addEventLog({
        type: 'success',
        message: 'ZTM passkey verified successfully',
        source: 'ztm'
      })
      return true
    }

    addEventLog({
      type: 'warning',
      message: 'Invalid ZTM passkey attempt',
      source: 'ztm'
    })
    return false
  }, [])

  // Enable ZTM
  const enableZeroTrust = useCallback(() => {
    console.log('[Zero Trust] 🚀 Activating Zero Trust Mode...')

    // Generate ephemeral session data
    const sessionKey = Array.from({ length: 32 }, () =>
      Math.floor(Math.random() * 256).toString(16).padStart(2, '0')
    ).join('')

    const words = [
      'quantum', 'lattice', 'cipher', 'void', 'neon', 'trust', 'zero', 'burn',
      'crypto', 'secure', 'ghost', 'shadow', 'black', 'red', 'green', 'pulse'
    ]

    const ephemeralIdentity = Array.from({ length: 4 }, () =>
      words[Math.floor(Math.random() * words.length)]
    ).join('-')

    setZeroTrustData({
      sessionKey,
      ephemeralIdentity,
      threatLevel: 'yellow'
    })
    setIsZeroTrustMode(true)
    setActiveRecipe('CHAOS_ONLY')
    setLastSwitchReason('ZTM activation - starting with baseline recipe')
    setLastSwitchTime(Date.now())

    // Send activation to backend
    sendMessage({
      type: 'ztm_activate_request',
      sessionKey,
      ephemeralIdentity,
      initialRecipe: 'CHAOS_ONLY'
    })

    addEventLog({
      type: 'recipe_switch',
      message: 'Zero Trust Mode activated with CHAOS_ONLY baseline',
      source: 'ztm',
      details: { ephemeralIdentity }
    })

    console.log('[Zero Trust] ✅ Mode activated with ephemeral identity:', ephemeralIdentity)
  }, [sendMessage])

  // Disable ZTM
  const disableZeroTrust = useCallback(() => {
    console.log('[Zero Trust] 🗑️ Deactivating Zero Trust Mode...')

    sendMessage({
      type: 'ztm_deactivate_request'
    })

    addEventLog({
      type: 'info',
      message: 'Zero Trust Mode deactivated - returning to Normal Mode',
      source: 'ztm'
    })

    setZeroTrustData({ threatLevel: 'green' })
    setIsZeroTrustMode(false)
    setIsPasskeyVerified(false)
    setActiveRecipe('CHAOS_ONLY')
    setLastSwitchReason(null)
    setLastSwitchTime(null)
    setHeuristics(DEFAULT_HEURISTICS)

    console.log('[Zero Trust] ✅ Mode deactivated, all data destroyed')
  }, [sendMessage])

  // Switch recipe
  const switchRecipe = useCallback((recipe: ZTMRecipeKey, reason?: string) => {
    // Cooldown check (5 seconds minimum)
    if (lastSwitchTime && Date.now() - lastSwitchTime < 5000) {
      addEventLog({
        type: 'warning',
        message: 'Recipe switch blocked - cooldown active (5s minimum)',
        source: 'ztm'
      })
      return
    }

    const switchReason = reason || `Manual switch to ${recipe}`
    setActiveRecipe(recipe)
    setLastSwitchReason(switchReason)
    setLastSwitchTime(Date.now())

    sendMessage({
      type: 'adaptive_switch_request',
      mode: 'ztm',
      recipe: recipe.toLowerCase()
    })

    addEventLog({
      type: 'recipe_switch',
      message: `Switched to ${recipe}: ${switchReason}`,
      source: 'ztm',
      details: { recipe, reason: switchReason }
    })

    console.log(`[Zero Trust] ⚡ Recipe switched to ${recipe}: ${switchReason}`)
  }, [lastSwitchTime, sendMessage])

  // Update heuristics
  const updateHeuristics = useCallback((metrics: Partial<HeuristicMetrics>) => {
    setHeuristics(prev => ({ ...prev, ...metrics }))
  }, [])

  // Track last threshold check to avoid duplicate alerts
  const lastThresholdCheck = useRef<number>(0)

  // Check thresholds on heuristics change - works in BOTH Normal and ZTM modes
  useEffect(() => {
    const now = Date.now()
    // Only check every 2 seconds to prevent spam
    if (now - lastThresholdCheck.current < 2000) return
    lastThresholdCheck.current = now

    // Check thresholds against current heuristics
    const triggers = checkThresholds(heuristics as ThresholdMetrics)

    for (const trigger of triggers) {
      // Check cooldown to prevent duplicate alerts
      if (!canTriggerAlert(trigger.profile.name, trigger.profile.cooldownSeconds)) {
        continue
      }

      // Generate alert (works in both modes)
      const newAlert: ThreatAlert = {
        id: `alert-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
        timestamp: Date.now(),
        type: trigger.profile.severity,
        attackType: trigger.profile.displayName,
        message: trigger.profile.reason,
        metric: trigger.metric,
        value: trigger.value,
        threshold: trigger.threshold,
        recipe: isZeroTrustMode ? trigger.profile.targetRecipe : undefined
      }
      setAlerts(prev => [newAlert, ...prev].slice(0, 50))

      // Log the alert
      addEventLog({
        type: 'threat',
        message: `${trigger.profile.displayName}: ${trigger.profile.reason}`,
        source: isZeroTrustMode ? 'ztm' : 'system',
        details: {
          metric: trigger.metric,
          value: trigger.value,
          threshold: trigger.threshold,
          mode: isZeroTrustMode ? 'ZTM' : 'NORMAL'
        }
      })

      // Only auto-switch recipe in ZTM mode
      if (isZeroTrustMode && trigger.profile.targetRecipe) {
        switchRecipe(trigger.profile.targetRecipe as ZTMRecipeKey, trigger.profile.reason)
      }

      console.log(`[Alert] ${isZeroTrustMode ? '🔴 ZTM' : '🟡 Normal'}: ${trigger.profile.displayName}`, {
        metric: trigger.metric,
        value: trigger.value,
        threshold: trigger.threshold,
        autoSwitch: isZeroTrustMode
      })
    }
  }, [heuristics, isZeroTrustMode])

  // Add alert
  const addAlert = useCallback((alert: Omit<ThreatAlert, 'id' | 'timestamp'>) => {
    const newAlert: ThreatAlert = {
      ...alert,
      id: `alert-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      timestamp: Date.now()
    }
    setAlerts(prev => [newAlert, ...prev].slice(0, 50)) // Keep max 50 alerts

    // Also log to event log
    addEventLog({
      type: 'threat',
      message: `${alert.attackType}: ${alert.message}`,
      source: 'ztm',
      details: {
        metric: alert.metric,
        value: alert.value,
        threshold: alert.threshold
      }
    })
  }, [])

  const dismissAlert = useCallback((id: string) => {
    setAlerts(prev => prev.filter(a => a.id !== id))
  }, [])

  const clearAlerts = useCallback(() => {
    setAlerts([])
  }, [])

  // Add event log
  const addEventLog = useCallback((entry: Omit<LogEntry, 'id' | 'timestamp'>) => {
    const newEntry: LogEntry = {
      ...entry,
      id: `log-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      timestamp: Date.now()
    }
    setEventLogs(prev => [...prev, newEntry].slice(-100)) // Keep last 100 logs
  }, [])

  const clearEventLogs = useCallback(() => {
    setEventLogs([])
  }, [])

  // Listen for WebSocket messages
  useEffect(() => {
    if (!lastMessage) return

    const { type, ...data } = lastMessage

    switch (type) {
      case 'ztm_activation_acknowledged':
        if (data.success) {
          setZeroTrustData(prev => ({ ...prev, threatLevel: 'green' }))
          addEventLog({
            type: 'success',
            message: 'Server acknowledged ZTM activation',
            source: 'server'
          })
        }
        break

      case 'adaptive_switch_acknowledged':
        addEventLog({
          type: 'success',
          message: `Recipe switch to ${data.recipe} acknowledged`,
          source: 'server'
        })
        break

      case 'heuristics_update':
        updateHeuristics(data.metrics)
        break

      case 'threat_alert':
        addAlert({
          type: data.severity || 'warning',
          attackType: data.attackType,
          message: data.message,
          metric: data.metric,
          value: data.value,
          threshold: data.threshold,
          recipe: data.recipeSwitched
        })

        // Auto-switch recipe in ZTM mode
        if (isZeroTrustMode && data.recipeSwitched) {
          setActiveRecipe(data.recipeSwitched as ZTMRecipeKey)
          setLastSwitchReason(data.reason || 'Automatic threat response')
          setLastSwitchTime(Date.now())
        }
        break

      case 'security_update':
        if (data.decrypt_failures !== undefined || data.hmac_failures !== undefined) {
          updateHeuristics({
            decryptFailures: data.decrypt_failures || 0,
            hmacFailures: data.hmac_failures || 0,
            replayAttempts: data.replay_attempts || 0
          })
        }
        break

      case 'decryption_update':
        // Extract live latency from actual decryption time
        if (data.decryptionTime !== undefined) {
          updateHeuristics({
            latencyMs: data.decryptionTime
          })
        }
        // Log the decryption event
        addEventLog({
          type: 'health',
          message: `Data decrypted in ${data.decryptionTime?.toFixed(2)}ms`,
          source: 'server',
          details: {
            plaintextLength: data.finalPlaintext?.length
          }
        })
        break

      case 'health_data_update':
        // Log health data from ESP32
        addEventLog({
          type: 'health',
          message: `Health: HR=${data.heartRate} SPO2=${data.spo2} Steps=${data.steps}`,
          source: 'esp32'
        })
        break
    }
  }, [lastMessage, isZeroTrustMode, updateHeuristics, addAlert, addEventLog])

  const value: ZeroTrustContextType = {
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
    updateHeuristics,
    alerts,
    addAlert,
    dismissAlert,
    clearAlerts,
    eventLogs,
    addEventLog,
    clearEventLogs,
    zeroTrustData
  }

  return (
    <ZeroTrustContext.Provider value={value}>
      {children}
    </ZeroTrustContext.Provider>
  )
}

// Hook to use Zero Trust context
export function useZeroTrust(): ZeroTrustContextType {
  const context = useContext(ZeroTrustContext)

  if (context === undefined) {
    throw new Error('useZeroTrust must be used within a ZeroTrustProvider')
  }

  return context
}

// Hook for security monitoring components
export function useZeroTrustSecurity() {
  const { isZeroTrustMode, zeroTrustData, heuristics, alerts } = useZeroTrust()

  const getSecurityStatus = useCallback(() => {
    return {
      isActive: isZeroTrustMode,
      threatLevel: zeroTrustData.threatLevel,
      activeAlerts: alerts.length,
      heuristics
    }
  }, [isZeroTrustMode, zeroTrustData.threatLevel, alerts.length, heuristics])

  return {
    securityStatus: getSecurityStatus(),
    isZeroTrustMode,
    zeroTrustData,
    heuristics,
    alerts
  }
}

export default ZeroTrustContext