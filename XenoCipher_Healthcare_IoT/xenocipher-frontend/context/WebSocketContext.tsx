// context/WebSocketContext.tsx
'use client'

import React, { createContext, useContext, useEffect, useRef, useState } from 'react'

interface WebSocketMessage {
  type: string
  [key: string]: any
}

// In WebSocketContext.tsx, update the context type:
interface WebSocketContextType {
  isConnected: boolean
  lastMessage: WebSocketMessage | null
  sendMessage: (message: WebSocketMessage) => void
  connectionStatus: 'connecting' | 'connected' | 'disconnected' | 'error'
  messageHistory: WebSocketMessage[] // Add this
}

export const WebSocketContext = createContext<WebSocketContextType | undefined>(undefined)

export function WebSocketProvider({ children }: { children: React.ReactNode }) {
  const [isConnected, setIsConnected] = useState(false)
  const [lastMessage, setLastMessage] = useState<WebSocketMessage | null>(null)
  const [messageHistory, setMessageHistory] = useState<WebSocketMessage[]>([])
  const [connectionStatus, setConnectionStatus] = useState<'connecting' | 'connected' | 'disconnected' | 'error'>('disconnected')

  const ws = useRef<WebSocket | null>(null)
  const reconnectTimeout = useRef<NodeJS.Timeout | undefined>(undefined)

  const connect = () => {
    try {
      setConnectionStatus('connecting')

      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
      const wsHost = process.env.NEXT_PUBLIC_WS_HOST || 'localhost'
      const wsPort = process.env.NEXT_PUBLIC_WS_PORT || '8081'
      const wsPath = process.env.NEXT_PUBLIC_WS_PATH || '/api/ws'

      const wsUrl = `${protocol}//${wsHost}:${wsPort}${wsPath}`
      console.log('[WebSocket] Connecting to:', wsUrl)

      ws.current = new WebSocket(wsUrl)

      ws.current.onopen = () => {
        console.log('[WebSocket] ✅ Connected successfully')
        setIsConnected(true)
        setConnectionStatus('connected')

        // Send hello message to server
        sendMessage({
          type: 'hello_from_frontend',
          client: 'xenocipher_dashboard',
          timestamp: Date.now()
        })
      }

      ws.current.onmessage = (event) => {
        try {
          const message = JSON.parse(event.data)
          console.log('[WebSocket] 📨 Received message:', message.type, message)

          setLastMessage(message)
          setMessageHistory(prev => [...prev.slice(-9), message]) // Keep last 10 messages
        } catch (error) {
          console.error('[WebSocket] ❌ Failed to parse message:', error, 'Raw data:', event.data)
        }
      }

      ws.current.onclose = (event) => {
        console.log('[WebSocket] 🔌 Disconnected:', event.code, event.reason)
        setIsConnected(false)
        setConnectionStatus('disconnected')

        // Attempt reconnect after 3 seconds
        if (reconnectTimeout.current) {
          clearTimeout(reconnectTimeout.current)
        }
        reconnectTimeout.current = setTimeout(() => {
          console.log('[WebSocket] 🔄 Attempting to reconnect...')
          connect()
        }, 3000)
      }

      ws.current.onerror = (error) => {
        console.error('[WebSocket] ❌ Error:', error)
        setConnectionStatus('error')
        setIsConnected(false)
      }

    } catch (error) {
      console.error('[WebSocket] ❌ Connection failed:', error)
      setConnectionStatus('error')
      setIsConnected(false)
    }
  }

  const sendMessage = (message: WebSocketMessage) => {
    if (ws.current && ws.current.readyState === WebSocket.OPEN) {
      try {
        ws.current.send(JSON.stringify(message))
        console.log('[WebSocket] 📤 Sent:', message.type, message)
      } catch (error) {
        console.error('[WebSocket] ❌ Failed to send message:', error)
      }
    } else {
      console.warn('[WebSocket] ⚠️ Cannot send message - connection not open')
    }
  }

  useEffect(() => {
    connect()

    return () => {
      if (reconnectTimeout.current) {
        clearTimeout(reconnectTimeout.current)
      }
      if (ws.current) {
        ws.current.close()
      }
    }
  }, [])

  const value: WebSocketContextType = {
    isConnected,
    lastMessage,
    sendMessage,
    connectionStatus,
    messageHistory
  }

  return (
    <WebSocketContext.Provider value={value}>
      {children}
    </WebSocketContext.Provider>
  )
}

export function useWebSocket() {
  const context = useContext(WebSocketContext)
  if (context === undefined) {
    throw new Error('useWebSocket must be used within a WebSocketProvider')
  }
  return context
}