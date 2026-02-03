// types/pipeline.ts

// Base pipeline step types
export type PipelineStep =
  | 'idle'
  | 'requesting_public_key'
  | 'encrypting_master_key'
  | 'sending_master_key'
  | 'master_key_established'
  | 'encrypting_data'
  | 'sending_data'
  | 'receiving_data'
  | 'decrypting_data'
  | 'completed'

export interface StepInfo {
  id: PipelineStep
  title: string
  description: string
  icon: string
  color: string
}

// Data interfaces
export interface HealthData {
  heartRate: number
  spo2: number
  steps: number
  temperature?: number
  timestamp?: number
}

export interface ESP32Data {
  plaintext?: string
  encryptedPacket?: string
  publicKey?: string
  masterKey?: string
  encryptionTime?: number
  encryptionDetails?: EncryptionDetails
}

export interface ServerData {
  decryptedData?: string
  healthData?: HealthData
  receivedPacket?: string
  decryptionTime?: number
  decryptionDetails?: DecryptionDetails
}

// Main pipeline data structure
export interface SequentialPipelineData {
  currentStep: PipelineStep
  previousStep: PipelineStep
  esp32Connected: boolean
  serverConnected: boolean
  esp32Data?: ESP32Data
  serverData?: ServerData
  lastUpdated: number
}

// Pipeline step props for components
export interface PipelineStepProps {
  step: StepInfo
  index: number
  isActive: boolean
  isCompleted: boolean
  isUpcoming: boolean
}

// New encryption/decryption details interfaces
export interface EncryptionDetails {
  plaintext: string
  lfsrOutput: string
  chaosMapOutput: string
  transpositionOutput: string
  finalEncryptedPacket: string
  metadata: {
    salt: string
    key: string
    iv: string
    authTag: string
    timestamp: number
  }
}

export interface DecryptionDetails {
  encryptedPacket: string
  reversedTransposition: string
  reversedChaosMap: string
  reversedLFSR: string
  finalPlaintext: string
  verification: {
    hmacValid: boolean
    integrityCheck: boolean
    timestampValid: boolean
  }
  timing: {
    totalTime: number
    decryptionTime: number
    verificationTime: number
  }
}

// Logging interfaces
export interface LogEntry {
  id: string
  timestamp: number
  type: 'info' | 'warning' | 'error' | 'success' | 'threat'
  message: string
  source: 'esp32' | 'server' | 'security' | 'pipeline'
}

// Enhanced pipeline data with new features
export interface PipelineData {
  currentStep: string
  esp32Connected: boolean
  serverConnected: boolean
  esp32Data: {
    plaintext?: string
    encryptedPacket?: string
    encryptionDetails?: EncryptionDetails
  }
  serverData: {
    decryptedData?: string
    healthData?: any
    decryptionDetails?: DecryptionDetails
  }
  logs: LogEntry[]
}

// WebSocket message types
export interface WebSocketMessage {
  type: string
  [key: string]: any
}

// Zero Trust types
export type ThreatLevel = 'green' | 'yellow' | 'red'

export interface ZeroTrustContextType {
  isZeroTrustMode: boolean
  enableZeroTrust: (passkey?: string) => void
  disableZeroTrust: () => void
  zeroTrustData: {
    sessionKey?: string
    ephemeralIdentity?: string
    threatLevel: ThreatLevel
  }
}