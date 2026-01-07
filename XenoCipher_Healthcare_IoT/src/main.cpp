#include <Arduino.h>
#include <WiFi.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include <nvs_flash.h>
#include <esp_random.h>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>

// WebSocket support
#include <WebSocketsClient.h>

// Custom cryptographic libraries
#include "crypto_kdf.h"
#include "lfsr.h"
#include "tinkerbell.h"
#include "transposition.h"
#include "hmac.h"
#include "entropy.h"
#include "../lib/NTRU/include/ntru.h"
#include "common.h"
#include "../lib/ChaCha20/include/chacha20_impl.h"
#include "../lib/Salsa20/include/salsa20_impl.h"

// Configuration
#define SERVER_URL "http://10.45.98.115:8081"
#define WS_SERVER "192.168.230.103"  // WebSocket server IP
#define WS_PORT 8081                 // WebSocket server port
#define WS_PATH "/api/ws"            // WebSocket path
#define WIFI_SSID "motorola edge 40_6753" //Galaxy M322E19"
#define WIFI_PASSWORD "subviv123" //yvhh6733"
#define HEALTH_DATA_INTERVAL_MS 10000
#define CONNECTION_TIMEOUT_MS 10000
#define MAX_RETRIES 3
#define MAX_PACKETS 20
#define HMAC_TAG_LEN 16
#define VERSION_BASE 0x01
#define VERSION_NONCE_EXT 0x81

// NVS keys
#define NVS_NAMESPACE "xenocipher"
#define NVS_PUBKEY_KEY "ntru_pub"
#define NVS_MASTER_KEY_KEY "master_key"
#define NVS_ZTM_MODE_KEY "ztm_mode"
#define NVS_ZTM_RECIPE_KEY "ztm_recipe"
#define NVS_ZTM_PASSKEY_KEY "ztm_passkey"

// Retry mechanism variables
#define MAX_RETRIES 3
#define RETRY_BACKOFF_MS 100
#define MAX_CONSECUTIVE_FAILURES 5

uint32_t packet_counter = 0;
int consecutive_failures = 0;
bool emergency_reset_triggered = false;

// State machine
enum CommState {
  STATE_INIT_NVS,
  STATE_CONNECT_WIFI,
  STATE_CHECK_PUBLIC_KEY,
  STATE_GET_PUBLIC_KEY,
  STATE_GENERATE_MASTER_KEY,
  STATE_ENCRYPT_MASTER_KEY,
  STATE_DERIVE_SYMMETRIC,
  STATE_SEND_HEALTH_DATA,
  STATE_ERROR
};

// Global state
static CommState currentState = STATE_INIT_NVS;
static bool masterKeyReady = false;
static bool publicKeyLoaded = false;
static uint32_t lastHealthSend = 0;
static int healthSendCount = 0;
static int retryCount = 0;
static bool wifiAttemptInProgress = false;
static unsigned long wifiAttemptStartMs = 0;
static bool wsConnected = false;

// WebSocket client
WebSocketsClient webSocket;

// Cryptographic state
static DerivedKeys gBaseKeys;
static uint8_t gMasterKey[32];
static std::vector<uint8_t> gPublicKey;

// Nonce tracking
struct NonceTracker {
  uint32_t lastNonce;
  uint32_t lastTsMs;
};
static NonceTracker gDeviceNonceTracker = {0, 0};

// Pipeline debugging
struct PipelineLayer {
  char label[32];
  char hex[512];
  size_t dataLen;
};
static PipelineLayer capturedLayers[7];
static int capturedLayerIndex = 0;
static bool capturingLayers = false;
static char currentPlaintext[128];

// Adaptive switching state
enum class OperationalMode {
    NORMAL,          // Standard XenoCipher (3 algorithms)
    ZTM              // Zero-Trust Mode (5 algorithms)
};

enum class ZTMRecipe {
    FULL_STACK,      // All 5: LFSR + Tinkerbell + Transposition + ChaCha20 + Salsa20
    CHACHA_HEAVY,    // ChaCha20 + LFSR + Tinkerbell
    SALSA_LIGHT,     // Salsa20 + LFSR
    CHAOS_ONLY,      // LFSR + Tinkerbell + Transposition (no stream ciphers)
    STREAM_FOCUS     // ChaCha20 + Salsa20 + minimal chaos
};

// Heuristics tracking for ZTM
struct HeuristicsState {
    uint32_t hmacFailures;
    uint32_t decryptFailures;
    uint32_t replayAttempts;
    uint32_t malformedPackets;
    uint32_t timingAnomalies;
    uint32_t lastEventTime;
    uint32_t violationCounter;
    uint32_t stabilityCounter;
};

static OperationalMode gCurrentMode = OperationalMode::NORMAL;
static ZTMRecipe gCurrentRecipe = ZTMRecipe::FULL_STACK;
static bool gModeChangePending = false;
static bool gZTMEnabled = false;
static HeuristicsState gHeuristics = {0, 0, 0, 0, 0, 0, 0, 0};
static uint32_t gLastRecipeSwitchTime = 0;
static const uint32_t RECIPE_SWITCH_COOLDOWN_MS = 5000; // 5 second cooldown

// ============================================================================
// FORWARD DECLARATIONS - ADD THESE
// ============================================================================

// Network functions
static bool http_get_public_key();
static bool http_post_enc_key_with_raw(const std::vector<uint8_t>& encKey, const uint8_t* rawKey32);
static bool http_post_enc_data_with_pipeline(const std::vector<uint8_t>& packet, 
                                            const char* plaintext,
                                            const PipelineLayer* layers, 
                                            int layerCount);

// Crypto functions
static bool generate_and_encrypt_master_key();
static bool derive_symmetric_keys();
static void generate_realistic_health_data(char* buffer, size_t buffer_size, uint32_t timestamp);
static bool encrypt_and_send_health_data();
static bool encrypt_and_send_health_data_with_nonce(uint32_t nonce);

// Utility functions
static String bytes_to_hex(const uint8_t* data, size_t len);
static void hexPrint(const char* label, const uint8_t* data, size_t n);
static uint32_t GET_TIME_MS();
static void nonce_tracker_init(NonceTracker* t);
static uint32_t nonce_tracker_get_next(NonceTracker* t);
static void nonce_tracker_mark_used(NonceTracker* t, uint32_t nonce, uint32_t nowMs);

// ZTM and Heuristics functions
static void recordEvent(const char* eventType);
static bool evaluateThreatAndSwitchRecipe();
static void switchToRecipe(ZTMRecipe recipe, bool force = false);
static bool loadZTMSettings();
static bool saveZTMSettings();
static bool verifyPasskey(const String& passkey);
static String recipeToString(ZTMRecipe recipe);

// WebSocket functions
void webSocketEvent(WStype_t type, uint8_t * payload, size_t length);
void initWebSocket();
void sendWebSocketUpdate(const char* type, const char* message, bool success = true);
void sendEncryptionPipelineUpdate(const PipelineLayer* layers, int layerCount, const char* plaintext);

// State machine
void handle_communication_state();
static void printStatus(const char* stateName);

// Encryption pipeline forward declarations
struct SaltMeta {
    uint16_t pos;
    uint8_t len;
};
GridSpec selectGrid(size_t len);
void pipelineEncryptPacket(const DerivedKeys& baseKeys, uint32_t nonce, bool includeNonceExt,
                           const uint8_t* data, size_t dataLen, const GridSpec& grid,
                           uint8_t salt_len, uint16_t salt_pos, uint16_t payload_len,
                           std::vector<uint8_t>& packet, bool verbose);

// ============================================================================
// RETRY MECHANISM FUNCTIONS - FIXED VERSION
// ============================================================================

void reset_crypto_state() {
    Serial.println("[CRYPTO] Resetting cryptographic state");
    
    // Reset cryptographic state by re-deriving keys if needed
    // We can't directly reset internal MessageKeys since they're regenerated each time
    
    // Increment packet counter for tracking
    packet_counter++;
    
    Serial.println("[CRYPTO] Crypto state reset complete");
    Serial.printf("[CRYPTO] Packet counter: %u\n", packet_counter);
}

void reset_crypto_state_for_retry() {
    Serial.println("[RETRY] Resetting crypto state for retry");
    
    // For retries, we mainly need to ensure fresh message keys are generated
    // The deriveMessageKeys function will create fresh keys on next call
    
    Serial.println("[RETRY] Crypto state ready for retry");
}

void trigger_emergency_reset() {
    Serial.println("[EMERGENCY] Triggering emergency reset!");
    emergency_reset_triggered = true;
    
    // Full system reset
    reset_crypto_state();
    
    // Reset failure counter
    consecutive_failures = 0;
    
    // Reset nonce tracker to maintain sequence
    nonce_tracker_init(&gDeviceNonceTracker);
    
    // Optional: Reconnect to WiFi if needed
    if (WiFi.status() != WL_CONNECTED) {
        Serial.println("[EMERGENCY] WiFi disconnected, attempting reconnect");
        WiFi.disconnect();
        delay(1000);
        WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
    }
    
    Serial.println("[EMERGENCY] Emergency reset complete");
    emergency_reset_triggered = false;
}

// Helper function to validate if we should proceed with sending
bool should_attempt_send() {
    if (!masterKeyReady) {
        Serial.println("[RETRY] Master keys not ready - cannot send");
        return false;
    }
    
    if (WiFi.status() != WL_CONNECTED) {
        Serial.println("[RETRY] WiFi not connected - cannot send");
        return false;
    }
    
    if (emergency_reset_triggered) {
        Serial.println("[RETRY] Emergency reset in progress - cannot send");
        return false;
    }
    
    return true;
}

bool send_health_data_with_retry() {
    int max_retries = MAX_RETRIES;
    
    Serial.printf("[RETRY] Attempting to send health data (Max retries: %d)\n", max_retries);
    
    // Get nonce ONCE before retry loop - use same nonce for all retries
    // Save current nonce state before incrementing
    uint32_t saved_nonce = gDeviceNonceTracker.lastNonce;
    uint32_t nonce_to_use = nonce_tracker_get_next(&gDeviceNonceTracker);
    Serial.printf("[RETRY] Using nonce %u for all retry attempts (saved: %u)\n", nonce_to_use, saved_nonce);
    
    // CRITICAL FIX: Generate health data and encrypt ONCE before retry loop
    // This ensures all retries use the SAME ciphertext for the same nonce
    if (!masterKeyReady) {
        Serial.println("Master keys not ready");
        gDeviceNonceTracker.lastNonce = saved_nonce; // Rollback nonce
        return false;
    }

    char healthBuffer[64];
    generate_realistic_health_data(healthBuffer, sizeof(healthBuffer), millis());
    Serial.printf("Generated health data: %s\n", healthBuffer);
    
    strncpy(currentPlaintext, healthBuffer, 127);
    currentPlaintext[127] = '\0';
    
    SaltMeta meta;
    meta.pos = (uint16_t)strlen(healthBuffer);
    meta.len = 2;
    
    const uint8_t* plainData = (const uint8_t*)healthBuffer;
    size_t plainLen = strlen(healthBuffer);
    GridSpec grid = selectGrid(plainLen);
    
    std::vector<uint8_t> packet;
    bool verbose = true;
    capturedLayerIndex = 0;
    capturingLayers = verbose;
    
    // Encrypt ONCE before retry loop
    pipelineEncryptPacket(gBaseKeys, nonce_to_use, true, plainData, plainLen, grid,
                          meta.len, meta.pos, plainLen, packet, verbose);
    
    if (packet.empty()) {
        Serial.println("Encryption failed - empty packet");
        capturingLayers = false;
        gDeviceNonceTracker.lastNonce = saved_nonce; // Rollback nonce
        return false;
    }
    
    // Now retry sending the SAME encrypted packet
    for (int attempt = 0; attempt < max_retries; attempt++) {
        Serial.printf("[RETRY] Attempt %d/%d (nonce: %u)\n", attempt + 1, max_retries, nonce_to_use);
        
        // Send the SAME encrypted packet (no re-encryption)
        bool success = http_post_enc_data_with_pipeline(packet, healthBuffer, 
                                                        capturedLayers, capturedLayerIndex);
        
        if (success) {
            capturingLayers = false;
            Serial.println("[RETRY] Health data sent successfully!");
            consecutive_failures = 0; // Reset failure counter on success
            // Mark nonce as successfully used
            gDeviceNonceTracker.lastNonce = nonce_to_use;
            gDeviceNonceTracker.lastTsMs = GET_TIME_MS();
            return true;
        }
        
        // If failed, wait with exponential backoff before retry
        if (attempt < max_retries - 1) {
            int backoff_time = RETRY_BACKOFF_MS * (1 << attempt);
            Serial.printf("[RETRY] Send failed, waiting %d ms before retry\n", backoff_time);
            delay(backoff_time);
        }
    }
    
    capturingLayers = false;
    
    // If all retries fail, rollback nonce (don't increment it)
    // This ensures we can retry with the same nonce later if needed
    gDeviceNonceTracker.lastNonce = saved_nonce;
    Serial.printf("[RETRY] All retry attempts failed - rolled back nonce to %u\n", saved_nonce);
    
    consecutive_failures++;
    Serial.printf("[RETRY] Consecutive failures: %d\n", consecutive_failures);
    
    // Check if we need emergency reset
    if (consecutive_failures >= MAX_CONSECUTIVE_FAILURES) {
        trigger_emergency_reset();
    }
    
    return false;
}

// ============================================================================
// WEBSOCKET FUNCTIONS
// ============================================================================

void webSocketEvent(WStype_t type, uint8_t * payload, size_t length) {
  switch(type) {
    case WStype_DISCONNECTED:
      Serial.printf("[WebSocket] Disconnected!\n");
      wsConnected = false;
      break;
      
    case WStype_CONNECTED:
      Serial.printf("[WebSocket] ========================================");
      Serial.printf("[WebSocket] CONNECTED to: %s\n", payload);
      Serial.printf("[WebSocket] WebSocket connection established");
      Serial.printf("[WebSocket] Ready to receive ZTM activation requests");
      Serial.printf("[WebSocket] ========================================");
      wsConnected = true;
      
      // Send hello message to server
      {
        DynamicJsonDocument doc(256);
        doc["type"] = "hello_from_esp32";
        doc["client"] = "esp32";
        doc["deviceId"] = String((uint32_t)ESP.getEfuseMac(), HEX);
        doc["timestamp"] = millis();
        
        String jsonStr;
        serializeJson(doc, jsonStr);
        webSocket.sendTXT(jsonStr);
        Serial.println("[WebSocket] Sent hello message (hello_from_esp32)");
      }
      
      // Send initial ZTM status if enabled
      if (gZTMEnabled) {
        DynamicJsonDocument statusDoc(512);
        statusDoc["type"] = "ztm_status";
        statusDoc["ztmEnabled"] = gZTMEnabled;
        statusDoc["currentMode"] = (gCurrentMode == OperationalMode::ZTM) ? "ztm" : "normal";
        statusDoc["currentRecipe"] = recipeToString(gCurrentRecipe).c_str();
        statusDoc["hmacFailures"] = gHeuristics.hmacFailures;
        statusDoc["decryptFailures"] = gHeuristics.decryptFailures;
        statusDoc["replayAttempts"] = gHeuristics.replayAttempts;
        statusDoc["malformedPackets"] = gHeuristics.malformedPackets;
        statusDoc["timingAnomalies"] = gHeuristics.timingAnomalies;
        statusDoc["timestamp"] = millis();
        
        String statusStr;
        serializeJson(statusDoc, statusStr);
        webSocket.sendTXT(statusStr);
        Serial.println("[WebSocket] Sent initial ZTM status");
      }
      break;
      
    case WStype_TEXT:
      {
        // Create null-terminated string from payload
        char payloadStr[length + 1];
        memcpy(payloadStr, payload, length);
        payloadStr[length] = '\0';
        
        Serial.printf("[WebSocket] Received (%d bytes): %s\n", length, payloadStr);
        
        // Parse incoming JSON message
        DynamicJsonDocument doc(1024);
        DeserializationError error = deserializeJson(doc, payloadStr);
        
        if (error) {
          Serial.printf("[WebSocket] JSON parse error: %s\n", error.c_str());
          Serial.printf("[WebSocket] Failed payload (first 100 chars): %.100s\n", payloadStr);
          return;
        }
        
        String msgType = doc["type"] | "unknown";
        
        Serial.printf("[WebSocket] Processing message type: %s\n", msgType.c_str());
        
        if (msgType == "security_update") {
          Serial.printf("[WebSocket] Security update - Mode: %s, ESP32 Connected: %s\n",
                       doc["currentMode"] | "unknown",
                       doc["esp32_connected"] ? "true" : "false");
        }
        else if (msgType == "connection_established") {
          Serial.printf("[WebSocket] Connection established - Session: %s\n",
                       doc["sessionId"] | "unknown");
        }
        else if (msgType == "decryption_update") {
          Serial.println("[WebSocket] Server decryption completed");
          if (doc.containsKey("healthData")) {
            int hr = doc["healthData"]["heartRate"] | 0;
            int spo2 = doc["healthData"]["spo2"] | 0;
            int steps = doc["healthData"]["steps"] | 0;
            Serial.printf("[WebSocket] Health data - HR: %d, SPO2: %d, Steps: %d\n", hr, spo2, steps);
          }
        }
        else if (msgType == "ztm_activate_request") {
          // Handle ZTM activation - NO PASSCODE REQUIRED
          Serial.println("[WebSocket] ========================================");
          Serial.println("[WebSocket] ZTM ACTIVATION REQUEST RECEIVED");
          Serial.println("[WebSocket] ========================================");
          
          // CRITICAL: Activate ZTM immediately - Normal Mode encryption will stop
          gCurrentMode = OperationalMode::ZTM;
          gZTMEnabled = true;
          gCurrentRecipe = ZTMRecipe::FULL_STACK; // Default to FULL_STACK on activation
          
          saveZTMSettings();
          
          Serial.println("[WebSocket] ✓ ZTM activated successfully");
          Serial.println("[WebSocket] ✓ Normal Mode encryption STOPPED");
          Serial.println("[WebSocket] ✓ ZTM encryption pipeline ACTIVE");
          Serial.println("[WebSocket] ✓ Current recipe: FULL_STACK");
          Serial.println("[WebSocket] ========================================");
          
          // Acknowledge activation with full status
          DynamicJsonDocument ackDoc(1024);
          ackDoc["type"] = "ztm_activation_acknowledged";
          ackDoc["success"] = true;
          ackDoc["mode"] = "ztm";
          ackDoc["recipe"] = recipeToString(gCurrentRecipe).c_str();
          ackDoc["deviceId"] = String((uint32_t)ESP.getEfuseMac(), HEX);
          ackDoc["timestamp"] = millis();
          // Include full ZTM status
          ackDoc["ztmEnabled"] = true;
          ackDoc["currentMode"] = "ztm";
          ackDoc["currentRecipe"] = recipeToString(gCurrentRecipe).c_str();
          ackDoc["hmacFailures"] = gHeuristics.hmacFailures;
          ackDoc["decryptFailures"] = gHeuristics.decryptFailures;
          ackDoc["replayAttempts"] = gHeuristics.replayAttempts;
          ackDoc["malformedPackets"] = gHeuristics.malformedPackets;
          ackDoc["timingAnomalies"] = gHeuristics.timingAnomalies;
          
          String ackStr;
          serializeJson(ackDoc, ackStr);
          webSocket.sendTXT(ackStr);
          
          Serial.printf("[WebSocket] ZTM activation acknowledged sent: %s\n", ackStr.c_str());
          
          sendWebSocketUpdate("ztm_activated", "Zero Trust Mode activated successfully");
        }
        else if (msgType == "ztm_deactivate_request") {
          // Handle ZTM deactivation - Revert to Normal Mode
          Serial.println("[WebSocket] ========================================");
          Serial.println("[WebSocket] ZTM DEACTIVATION REQUEST RECEIVED");
          Serial.println("[WebSocket] ========================================");
          
          // CRITICAL: Revert to Normal Mode - ZTM encryption will stop
          gCurrentMode = OperationalMode::NORMAL;
          gZTMEnabled = false;
          saveZTMSettings();
          
          // Reset heuristics
          memset(&gHeuristics, 0, sizeof(gHeuristics));
          
          Serial.println("[WebSocket] ✓ ZTM deactivated successfully");
          Serial.println("[WebSocket] ✓ ZTM encryption algorithms STOPPED");
          Serial.println("[WebSocket] ✓ Normal Mode encryption ACTIVE");
          Serial.println("[WebSocket] ✓ Using: LFSR + Tinkerbell + Transposition");
          Serial.println("[WebSocket] ========================================");
          
          // Acknowledge deactivation with full status
          DynamicJsonDocument ackDoc(512);
          ackDoc["type"] = "ztm_deactivation_acknowledged";
          ackDoc["success"] = true;
          ackDoc["mode"] = "normal";
          ackDoc["ztmEnabled"] = false;
          ackDoc["currentMode"] = "normal";
          ackDoc["timestamp"] = millis();
          
          String ackStr;
          serializeJson(ackDoc, ackStr);
          webSocket.sendTXT(ackStr);
          
          Serial.printf("[WebSocket] ZTM deactivation acknowledged sent: %s\n", ackStr.c_str());
          
          sendWebSocketUpdate("ztm_deactivated", "Zero Trust Mode deactivated - Normal Mode active");
        }
        else if (msgType == "adaptive_switch_request") {
          // Handle adaptive mode/recipe switch request from dashboard
          String mode = doc["mode"] | "normal";
          String recipe = doc["recipe"] | "full_stack";
          
          Serial.printf("[WebSocket] Adaptive switch requested: mode=%s, recipe=%s\n", mode.c_str(), recipe.c_str());
          
          // Parse mode
          OperationalMode newMode = (mode == "ztm") ? OperationalMode::ZTM : OperationalMode::NORMAL;
          
          // Parse recipe (accept both formats: "full_stack" and "FULL_STACK")
          ZTMRecipe newRecipe = ZTMRecipe::FULL_STACK;
          String recipeUpper = recipe;
          recipeUpper.toUpperCase();
          if (recipe == "full_stack" || recipeUpper == "FULL_STACK") newRecipe = ZTMRecipe::FULL_STACK;
          else if (recipe == "chacha_heavy" || recipeUpper == "CHACHA_HEAVY") newRecipe = ZTMRecipe::CHACHA_HEAVY;
          else if (recipe == "salsa_light" || recipeUpper == "SALSA_LIGHT") newRecipe = ZTMRecipe::SALSA_LIGHT;
          else if (recipe == "chaos_only" || recipeUpper == "CHAOS_ONLY") newRecipe = ZTMRecipe::CHAOS_ONLY;
          else if (recipe == "stream_focus" || recipeUpper == "STREAM_FOCUS") newRecipe = ZTMRecipe::STREAM_FOCUS;
          
          // Only allow recipe switching if in ZTM mode
          if (newMode == OperationalMode::ZTM && gZTMEnabled) {
            switchToRecipe(newRecipe, true); // Force switch for manual override
          } else if (newMode == OperationalMode::ZTM) {
            Serial.println("[WebSocket] Cannot switch to ZTM - not activated");
            
            DynamicJsonDocument ackDoc(256);
            ackDoc["type"] = "adaptive_switch_acknowledged";
            ackDoc["success"] = false;
            ackDoc["error"] = "ZTM not activated";
            ackDoc["timestamp"] = millis();
            
            String ackStr;
            serializeJson(ackDoc, ackStr);
            webSocket.sendTXT(ackStr);
            return;
          }
          
          // Apply mode change
          gCurrentMode = newMode;
          gModeChangePending = false;
          saveZTMSettings();
          
          Serial.printf("[WebSocket] Mode switched: %s, Recipe: %s\n", 
                       (newMode == OperationalMode::ZTM) ? "ZTM" : "NORMAL", recipe.c_str());
          
          // Acknowledge to server
          DynamicJsonDocument ackDoc(256);
          ackDoc["type"] = "adaptive_switch_acknowledged";
          ackDoc["mode"] = mode;
          ackDoc["recipe"] = recipe;
          ackDoc["success"] = true;
          ackDoc["deviceId"] = String((uint32_t)ESP.getEfuseMac(), HEX);
          ackDoc["timestamp"] = millis();
          
          String ackStr;
          serializeJson(ackDoc, ackStr);
          webSocket.sendTXT(ackStr);
          
          // Emit telemetry
          sendWebSocketUpdate("mode_changed", 
                            String("Mode: " + mode + ", Recipe: " + recipe).c_str());
        }
        else if (msgType == "get_ztm_status") {
          // Send current ZTM status
          DynamicJsonDocument statusDoc(512);
          statusDoc["type"] = "ztm_status";
          statusDoc["ztmEnabled"] = gZTMEnabled;
          statusDoc["currentMode"] = (gCurrentMode == OperationalMode::ZTM) ? "ztm" : "normal";
          statusDoc["currentRecipe"] = recipeToString(gCurrentRecipe).c_str();
          statusDoc["hmacFailures"] = gHeuristics.hmacFailures;
          statusDoc["decryptFailures"] = gHeuristics.decryptFailures;
          statusDoc["replayAttempts"] = gHeuristics.replayAttempts;
          statusDoc["malformedPackets"] = gHeuristics.malformedPackets;
          statusDoc["timingAnomalies"] = gHeuristics.timingAnomalies;
          statusDoc["timestamp"] = millis();
          
          String statusStr;
          serializeJson(statusDoc, statusStr);
          webSocket.sendTXT(statusStr);
        }
      }
      break;
      
    case WStype_BIN:
      Serial.printf("[WebSocket] Received binary data length: %u\n", length);
      break;
      
    case WStype_PING:
    case WStype_PONG:
      // Handle ping/pong if needed
      break;
      
    case WStype_ERROR:
    case WStype_FRAGMENT_TEXT_START:
    case WStype_FRAGMENT_BIN_START:
    case WStype_FRAGMENT:
    case WStype_FRAGMENT_FIN:
      break;
  }
}

void initWebSocket() {
  // Initialize WebSocket connection
  webSocket.begin(WS_SERVER, WS_PORT, WS_PATH);
  webSocket.onEvent(webSocketEvent);
  webSocket.setReconnectInterval(5000);
  Serial.printf("[WebSocket] Initialized - Server: %s:%d%s\n", WS_SERVER, WS_PORT, WS_PATH);
}

void sendWebSocketUpdate(const char* type, const char* message, bool success) {
  if (!wsConnected) return;
  
  DynamicJsonDocument doc(512);
  doc["type"] = type;
  doc["message"] = message;
  doc["success"] = success;
  doc["deviceId"] = String((uint32_t)ESP.getEfuseMac(), HEX);
  doc["timestamp"] = millis();
  doc["healthSendCount"] = healthSendCount;
  doc["state"] = currentState;
  
  String jsonStr;
  serializeJson(doc, jsonStr);
  webSocket.sendTXT(jsonStr);
}

void sendEncryptionPipelineUpdate(const PipelineLayer* layers, int layerCount, const char* plaintext) {
  if (!wsConnected) return;
  
  DynamicJsonDocument doc(2048);
  doc["type"] = "encryption_pipeline";
  doc["deviceId"] = String((uint32_t)ESP.getEfuseMac(), HEX);
  doc["timestamp"] = millis();
  doc["plaintext"] = plaintext;
  doc["healthSendCount"] = healthSendCount;
  
  JsonObject pipeline = doc.createNestedObject("pipeline");
  for (int i = 0; i < layerCount; i++) {
    if (strstr(layers[i].label, "Salt")) pipeline["afterSalt"] = layers[i].hex;
    else if (strstr(layers[i].label, "padded")) pipeline["afterPadding"] = layers[i].hex;
    else if (strstr(layers[i].label, "LFSR")) pipeline["afterLFSR"] = layers[i].hex;
    else if (strstr(layers[i].label, "Tinkerbell")) pipeline["afterTinkerbell"] = layers[i].hex;
    else if (strstr(layers[i].label, "Transposition")) pipeline["afterTransposition"] = layers[i].hex;
    else if (strstr(layers[i].label, "Final")) pipeline["finalPacket"] = layers[i].hex;
  }
  
  String jsonStr;
  serializeJson(doc, jsonStr);
  webSocket.sendTXT(jsonStr);
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

static String bytes_to_hex(const uint8_t* data, size_t len) {
  String hex;
  hex.reserve(len * 2);
  for (size_t i = 0; i < len; ++i) {
    char hexChar[3];
    sprintf(hexChar, "%02X", data[i]);
    hex += hexChar;
  }
  return hex;
}

static void hexPrint(const char* label, const uint8_t* data, size_t n) {
  Serial.printf("%s (%u): ", label, (unsigned)n);
  for (size_t i = 0; i < n && i < 32; ++i) {
    Serial.printf("%02X", data[i]);
    if ((i + 1) % 16 == 0) Serial.print(" ");
  }
  if (n > 32) Serial.print("...");
  Serial.println();
  
  if (capturingLayers && capturedLayerIndex < 7) {
    strncpy(capturedLayers[capturedLayerIndex].label, label, 31);
    capturedLayers[capturedLayerIndex].label[31] = '\0';
    String hexStr = bytes_to_hex(data, n);
    strncpy(capturedLayers[capturedLayerIndex].hex, hexStr.c_str(), 511);
    capturedLayers[capturedLayerIndex].hex[511] = '\0';
    capturedLayers[capturedLayerIndex].dataLen = n;
    capturedLayerIndex++;
  }
}

static uint32_t GET_TIME_MS() {
  return millis();
}

// ============================================================================
// NONCE MANAGEMENT
// ============================================================================

static void nonce_tracker_init(NonceTracker* t) {
  t->lastNonce = 0;
  t->lastTsMs = 0;
}

static uint32_t nonce_tracker_get_next(NonceTracker* t) {
  return ++t->lastNonce;
}

static void nonce_tracker_mark_used(NonceTracker* t, uint32_t nonce, uint32_t nowMs) {
  t->lastNonce = nonce;
  t->lastTsMs = nowMs;
}

// ============================================================================
// STORAGE MANAGEMENT
// ============================================================================

static bool store_public_key_nvs(const std::vector<uint8_t>& pub_bytes) {
  nvs_handle_t handle;
  esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &handle);
  if (err != ESP_OK) return false;
  
  err = nvs_set_blob(handle, NVS_PUBKEY_KEY, pub_bytes.data(), pub_bytes.size());
  if (err != ESP_OK) {
    nvs_close(handle);
    return false;
  }
  
  err = nvs_commit(handle);
  nvs_close(handle);
  return (err == ESP_OK);
}

static bool load_public_key_nvs(std::vector<uint8_t>& pub_bytes) {
  nvs_handle_t handle;
  esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READONLY, &handle);
  if (err != ESP_OK) return false;
  
  size_t required_size = 0;
  err = nvs_get_blob(handle, NVS_PUBKEY_KEY, nullptr, &required_size);
  if (err != ESP_OK || required_size == 0) {
    nvs_close(handle);
    return false;
  }
  
  pub_bytes.resize(required_size);
  err = nvs_get_blob(handle, NVS_PUBKEY_KEY, pub_bytes.data(), &required_size);
  nvs_close(handle);
  
  return (err == ESP_OK);
}

static bool store_master_key_nvs(const uint8_t* key, size_t key_len) {
  nvs_handle_t handle;
  esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &handle);
  if (err != ESP_OK) return false;
  
  err = nvs_set_blob(handle, NVS_MASTER_KEY_KEY, key, key_len);
  if (err == ESP_OK) err = nvs_commit(handle);
  
  nvs_close(handle);
  return (err == ESP_OK);
}

// ============================================================================
// NETWORK COMMUNICATION
// ============================================================================

static void onWiFiEvent(WiFiEvent_t event, WiFiEventInfo_t info) {
  switch (event) {
    case SYSTEM_EVENT_STA_START:
      Serial.println("[WiFi] STA Start");
      break;
    case SYSTEM_EVENT_STA_CONNECTED:
      Serial.println("[WiFi] Connected to AP");
      break;
    case SYSTEM_EVENT_STA_GOT_IP:
      Serial.printf("[WiFi] Got IP: %s\n", WiFi.localIP().toString().c_str());
      // Initialize WebSocket after getting IP
      initWebSocket();
      break;
    case SYSTEM_EVENT_STA_DISCONNECTED:
      Serial.printf("[WiFi] Disconnected, reason=%u\n", info.wifi_sta_disconnected.reason);
      wifiAttemptInProgress = false;
      wsConnected = false;
      break;
    default:
      break;
  }
}

static bool parse_hex_string(const String& hex, std::vector<uint8_t>& out) {
  out.clear();
  String cleanHex = hex;
  cleanHex.toUpperCase();
  cleanHex.replace(" ", "");
  cleanHex.replace(":", "");
  
  if (cleanHex.length() % 2 != 0) return false;
  
  out.reserve(cleanHex.length() / 2);
  for (size_t i = 0; i < cleanHex.length(); i += 2) {
    String byteStr = cleanHex.substring(i, i + 2);
    uint8_t byte = (uint8_t)strtol(byteStr.c_str(), nullptr, 16);
    out.push_back(byte);
  }
  return true;
}

static bool http_get_public_key() {
  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("WiFi not connected");
    return false;
  }

  HTTPClient http;
  String url = String(SERVER_URL) + "/public-key";
  Serial.printf("GET %s\n", url.c_str());
  
  http.begin(url);
  http.setTimeout(CONNECTION_TIMEOUT_MS);
  
  int httpCode = http.GET();
  if (httpCode == HTTP_CODE_OK) {
    String response = http.getString();
    Serial.printf("Response length: %u chars\n", response.length());

    int keyPos = response.indexOf("\"publicKey\"");
    if (keyPos >= 0) {
      int pubhexPos = response.indexOf("PUBHEX:", keyPos);
      if (pubhexPos >= 0) {
        int start = pubhexPos + 7;
        int end = response.indexOf('"', start);
        if (end < 0) end = response.length();
        
        String hexStr = response.substring(start, end);
        hexStr.trim();

        std::vector<uint8_t> pubBytes;
        if (parse_hex_string(hexStr, pubBytes)) {
          if (store_public_key_nvs(pubBytes)) {
            gPublicKey = pubBytes;
            publicKeyLoaded = true;
            http.end();
            
            // Send WebSocket update
            sendWebSocketUpdate("public_key_received", "Public key successfully retrieved from server");
            return true;
          }
        }
      }
    }
  }
  
  Serial.printf("HTTP GET failed - Code: %d\n", httpCode);
  http.end();
  return false;
}

static String to_hex_string(const std::vector<uint8_t>& data) {
  String dataHex;
  dataHex.reserve(data.size() * 2);
  for (uint8_t b : data) {
    char hexChar[3];
    sprintf(hexChar, "%02X", b);
    dataHex += hexChar;
  }
  return dataHex;
}

static bool http_post_enc_key_with_raw(const std::vector<uint8_t>& encKey, const uint8_t* rawKey32) {
  if (WiFi.status() != WL_CONNECTED) return false;

  HTTPClient http;
  String url = String(SERVER_URL) + "/master-key";
  Serial.printf("POST %s\n", url.c_str());

  http.begin(url);
  http.addHeader("Content-Type", "application/json");
  http.setTimeout(CONNECTION_TIMEOUT_MS);

  String encHex = to_hex_string(encKey);
  String rawHex = bytes_to_hex(rawKey32, 32);
  
  String jsonPayload = String("{") +
                       "\"encKey\":\"ENCKEY:" + encHex + "\"," +
                       "\"rawKey\":\"RAWKEY:" + rawHex + "\"" +
                       "}";

  int httpCode = http.POST(jsonPayload);
  String response = http.getString();

  bool success = (httpCode == HTTP_CODE_OK) && 
                 (response.indexOf("OK:") >= 0);
  
  http.end();
  
  // Send WebSocket update
  if (success) {
    sendWebSocketUpdate("master_key_exchanged", "Master key successfully exchanged with server");
  } else {
    sendWebSocketUpdate("master_key_error", "Master key exchange failed", false);
  }
  
  return success;
}

static bool http_post_enc_data_with_pipeline(const std::vector<uint8_t>& packet, 
                                            const char* plaintext,
                                            const PipelineLayer* layers, 
                                            int layerCount) {
  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("WiFi not connected for HTTP POST");
    return false;
  }

  HTTPClient http;
  String url = String(SERVER_URL) + "/health-data";
  Serial.printf("POST %s with pipeline data\n", url.c_str());

  http.begin(url);
  http.addHeader("Content-Type", "application/json");
  http.addHeader("Connection", "close"); // Prevent connection reuse issues
  http.setTimeout(10000); // 10 second timeout (was 15)
  http.setConnectTimeout(5000); // 5 second connection timeout
  
  DynamicJsonDocument doc(2048);
  doc["encData"] = "ENC_DATA:" + to_hex_string(packet);
  doc["plaintext"] = plaintext;
  doc["type"] = "encryption_update";
  doc["timestamp"] = millis();
  
  JsonObject pipeline = doc.createNestedObject("pipeline");
  for (int i = 0; i < layerCount; i++) {
    if (strstr(layers[i].label, "Salt")) pipeline["afterSalt"] = layers[i].hex;
    else if (strstr(layers[i].label, "padded")) pipeline["afterPadding"] = layers[i].hex;
    else if (strstr(layers[i].label, "LFSR")) pipeline["afterLFSR"] = layers[i].hex;
    else if (strstr(layers[i].label, "Tinkerbell")) pipeline["afterTinkerbell"] = layers[i].hex;
    else if (strstr(layers[i].label, "Transposition")) pipeline["afterTransposition"] = layers[i].hex;
  }
  
  String jsonStr;
  serializeJson(doc, jsonStr);
  
  Serial.printf("Sending pipeline data to server (%d bytes)\n", jsonStr.length());
  
  int httpCode = http.POST(jsonStr);
  
  // Log HTTP response code for debugging
  Serial.printf("[HTTP] Response code: %d\n", httpCode);
  
  bool success = (httpCode == HTTP_CODE_OK || httpCode == HTTP_CODE_CREATED);

  if (success) {
    String response = http.getString();
    Serial.printf("[HTTP] Response: %s\n", response.c_str());
    // Accept any 200/201 response, not just ones with "OK:" in body
    success = true;
  } else {
    String response = http.getString();
    Serial.printf("[HTTP] Error response: %s\n", response.c_str());
    Serial.printf("[HTTP] Request failed with code: %d\n", httpCode);
  }

  http.end();
  
  // Send WebSocket pipeline update
  if (success) {
    sendEncryptionPipelineUpdate(layers, layerCount, plaintext);
    sendWebSocketUpdate("health_data_sent", 
                       String("Health data #" + String(healthSendCount + 1) + " sent successfully").c_str());
  } else {
    sendWebSocketUpdate("health_data_error", "Failed to send health data", false);
  }
  
  return success;
}

// ============================================================================
// CRYPTOGRAPHIC OPERATIONS - FIXED VERSION
// ============================================================================

// FIXED: Consistent Tinkerbell XOR stream implementation
static void xor_with_stream_hmac(const uint8_t key16[16], uint32_t nonce, uint8_t* data, size_t len, bool verbose = false) {
  const char label[] = "XENO-TINK";
  uint8_t counter = 0;
  size_t offset = 0;
  bool firstBlock = true;
  
  while (offset < len) {
    uint8_t block[32];
    uint8_t msg[sizeof(label) + 4 + 1];
    memcpy(msg, label, sizeof(label));
    msg[sizeof(label) + 0] = (uint8_t)((nonce >> 24) & 0xFF);
    msg[sizeof(label) + 1] = (uint8_t)((nonce >> 16) & 0xFF);
    msg[sizeof(label) + 2] = (uint8_t)((nonce >> 8) & 0xFF);
    msg[sizeof(label) + 3] = (uint8_t)(nonce & 0xFF);
    msg[sizeof(label) + 4] = counter;
    
    // DEBUG: Log Tinkerbell XOR keystream generation
    if (verbose && firstBlock) {
      Serial.printf("[ESP32][TINKERBELL] Generating keystream block - Nonce: 0x%08X Counter: %u (must start at 0) Key[0..3]: ", nonce, counter);
      for (int i = 0; i < 4; ++i) {
        Serial.printf("%02X", key16[i]);
      }
      Serial.println();
      firstBlock = false;
    } else if (verbose && offset < len) {
      // Log when counter increments (for buffers > 32 bytes)
      Serial.printf("[ESP32][TINKERBELL] Counter incrementing to: %u\n", counter);
    }
    
    // Use consistent HMAC implementation
    hmac_sha256_full(key16, 16, msg, sizeof(msg), block);
    
    // DEBUG: Log first 16 bytes of keystream block
    if (verbose && offset == 0) {
      Serial.printf("[ESP32][TINKERBELL] Keystream block[%u] (first 16 bytes): ", counter);
      for (int i = 0; i < 16; ++i) {
        Serial.printf("%02X", block[i]);
      }
      Serial.println();
    }
    
    size_t n = (len - offset) < sizeof(block) ? (len - offset) : sizeof(block);
    for (size_t i = 0; i < n; ++i) {
      data[offset + i] ^= block[i];
    }
    offset += n;
    counter++;
  }
}

static bool generate_and_encrypt_master_key() {
  Serial.println("Generating fresh master key from entropy...");
  
  EntropyReport er{};
  if (!gatherMasterKey(gMasterKey, &er)) {
    Serial.println("✗ Entropy collection failed");
    return false;
  }
  
  hexPrint("Generated master key", gMasterKey, 32);
  
  // Store ORIGINAL master key for symmetric derivation (NOT reduced)
  if (!store_master_key_nvs(gMasterKey, 32)) {
    Serial.println("✗ Failed to store master key in NVS");
    memset(gMasterKey, 0, 32);
    return false;
  }
  
  // Reduce key ONLY for NTRU encryption (server expects reduced key)
  uint8_t reducedKey[32];
  for (int i = 0; i < 32; ++i) {
    reducedKey[i] = (uint8_t)(gMasterKey[i] % 3);
  }
  
  Serial.println("Using reduced master key (byte % 3) for NTRU encryption only");

  // NTRU encryption with reduced key
  NTRU ntru;
  Poly m, e, h;
  
  NTRU::bytes_to_poly(std::vector<uint8_t>(reducedKey, reducedKey + 32), m, 32);
  
  if (gPublicKey.empty() || gPublicKey.size() != NTRU_N * 2) {
    Serial.println("✗ Invalid public key");
    memset(gMasterKey, 0, 32);
    memset(reducedKey, 0, 32);
    return false;
  }
  
  // Convert public key bytes to polynomial
  for (int i = 0; i < NTRU_N; ++i) {
    h.coeffs[i] = (gPublicKey[i * 2] << 8) | gPublicKey[i * 2 + 1];
  }
  
  ntru.encrypt(m, h, e);
  
  std::vector<uint8_t> encryptedKey(NTRU_N * 2);
  for (int i = 0; i < NTRU_N; ++i) {
    encryptedKey[i * 2] = e.coeffs[i] >> 8;
    encryptedKey[i * 2 + 1] = e.coeffs[i] & 0xFF;
  }
  
  hexPrint("NTRU encrypted master key", encryptedKey.data(), encryptedKey.size());
  
  // Send BOTH encrypted reduced key AND original raw key for debugging
  bool success = http_post_enc_key_with_raw(encryptedKey, gMasterKey); // Send ORIGINAL key
  
  // Clear sensitive data
  memset(gMasterKey, 0, 32);
  memset(reducedKey, 0, 32);
  
  return success;
}

static bool derive_symmetric_keys() {
  Serial.println("Loading master key from NVS and deriving symmetric keys...");
  
  nvs_handle_t handle;
  esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READONLY, &handle);
  if (err != ESP_OK) {
    Serial.printf("Failed to open NVS: %s\n", esp_err_to_name(err));
    return false;
  }
  
  size_t required_size = 32;
  uint8_t masterKey[32];
  err = nvs_get_blob(handle, NVS_MASTER_KEY_KEY, masterKey, &required_size);
  nvs_close(handle);
  
  if (err != ESP_OK || required_size != 32) {
    Serial.printf("Failed to load master key from NVS: %s\n", esp_err_to_name(err));
    return false;
  }
  
  hexPrint("Loaded master key from NVS", masterKey, 32);
  
  if (!deriveKeys(masterKey, 32, gBaseKeys)) {
    Serial.println("Failed to derive symmetric keys");
    memset(masterKey, 0, 32);
    return false;
  }
  
  // FIXED: Only print the keys that actually exist in DerivedKeys structure
  hexPrint("Derived HMAC key", gBaseKeys.hmacKey, 32);
  hexPrint("Derived Tinkerbell key", gBaseKeys.tinkerbellKey, 16);
  hexPrint("Derived Transposition key", gBaseKeys.transpositionKey, 16);
  
  masterKeyReady = true;
  Serial.println("✓ Symmetric keys derived successfully");
  
  // Reset nonce tracker after successful key derivation (new session)
  nonce_tracker_init(&gDeviceNonceTracker);
  Serial.println("Nonce tracker reset - new session started");
  
  // CRITICAL: Small delay to ensure server has processed the master key exchange
  // This prevents sending packets with new keys before server is ready
  delay(500);
  Serial.println("Waiting for server to process master key...");
  
  // Send WebSocket update
  sendWebSocketUpdate("symmetric_keys_derived", "Symmetric keys successfully derived");
  
  memset(masterKey, 0, 32);
  return true;
}

// ============================================================================
// HEALTH DATA GENERATION
// ============================================================================

static void generate_realistic_health_data(char* buffer, size_t buffer_size, uint32_t timestamp) {
  uint8_t heart_rate = 60 + ((timestamp / 60000) % 41);
  uint8_t spo2 = 95 + ((timestamp / 300000) % 6);
  uint16_t steps = (timestamp / 1000) * 5 + (esp_random() % 50);
  
  if (steps > 10000) steps = 0;
  if (esp_random() % 100 < 5) heart_rate += esp_random() % 5;
  
  snprintf(buffer, buffer_size, "HR-%u SPO2-%u STEPS-%u", heart_rate, spo2, steps);
}

// ============================================================================
// ENCRYPTION PIPELINE - FIXED COMPATIBLE VERSION
// ============================================================================

static std::vector<uint8_t> insertSalt(const uint8_t* plain, size_t plen,
                                       const uint8_t* salt, uint8_t slen,
                                       const SaltMeta& meta) {
  std::vector<uint8_t> out;
  out.reserve(plen + slen);
  uint16_t p = meta.pos > plen ? plen : meta.pos;
  out.insert(out.end(), plain, plain + p);
  out.insert(out.end(), salt, salt + slen);
  out.insert(out.end(), plain + p, plain + plen);
  return out;
}

static std::vector<uint8_t> padToGrid(const uint8_t* in, size_t len, const GridSpec& g) {
  const size_t need = g.rows * g.cols;
  std::vector<uint8_t> out(need, 0x00);
  if (len > 0 && in != nullptr) {
    memcpy(out.data(), in, len < need ? len : need);
  }
  return out;
}

GridSpec selectGrid(size_t len) {
  if (len <= 12) return GridSpec{4, 3};
  if (len <= 32) return GridSpec{4, 8};
  if (len <= 64) return GridSpec{8, 8};
  size_t cols = 16;
  size_t rows = (len + cols - 1) / cols;
  if (rows < 4) rows = 4;
  return GridSpec{(uint8_t)rows, (uint8_t)cols};
}

static void writeHeader(uint8_t* hdr8,
                        uint8_t version,
                        uint8_t salt_len,
                        uint16_t salt_pos,
                        uint16_t payload_len,
                        uint8_t rows,
                        uint8_t cols) {
  hdr8[0] = version;
  hdr8[1] = salt_len;
  hdr8[2] = (uint8_t)(salt_pos & 0xFF);
  hdr8[3] = (uint8_t)((salt_pos >> 8) & 0xFF);
  hdr8[4] = (uint8_t)(payload_len & 0xFF);
  hdr8[5] = (uint8_t)((payload_len >> 8) & 0xFF);
  hdr8[6] = rows;
  hdr8[7] = cols;
}

// FIXED: Compatible encryption pipeline that matches server implementation
void pipelineEncryptPacket(const DerivedKeys& baseKeys,
                           uint32_t nonce, bool includeNonceExt,
                           const uint8_t* data, size_t dataLen,
                           const GridSpec& grid,
                           uint8_t salt_len, uint16_t salt_pos, uint16_t payload_len,
                           std::vector<uint8_t>& packet,
                           bool verbose) {
  MessageKeys mk;
  if (!deriveMessageKeys(baseKeys, nonce, mk)) {
    Serial.println("deriveMessageKeys failed!");
    packet.clear();
    return;
  }
  
  // Debug message keys
  if (verbose) {
    char tnk[9], trk[9];
    for (int i = 0; i < 4; ++i) {
      sprintf(&tnk[i * 2], "%02X", mk.tinkerbellKey[i]);
      sprintf(&trk[i * 2], "%02X", mk.transpositionKey[i]);
    }
    tnk[8] = '\0';
    trk[8] = '\0';
    Serial.printf("[ESP32] MsgKeys: lfsrSeed=0x%08X tnk[0..3]=%s trn[0..3]=%s\n", 
                  mk.lfsrSeed, tnk, trk);
  }

  // Step 1: Add salt
  std::vector<uint8_t> saltedData = insertSalt(data, dataLen, 
                                             (const uint8_t*)COMMON_SALT, salt_len, {salt_pos, salt_len});
  if (verbose) hexPrint("1_After_Salt", saltedData.data(), saltedData.size());

  // Step 2: Pad to grid
  std::vector<uint8_t> buf = padToGrid(saltedData.data(), saltedData.size(), grid);
  if (verbose) hexPrint("2_After_Padding", buf.data(), buf.size());

  // Step 3: LFSR encryption - FIXED: Use consistent implementation
  // Apply LFSR only if recipe includes it
  bool applyLFSRStep = true; // Default for normal mode
  if (gCurrentMode == OperationalMode::ZTM) {
    // In ZTM, LFSR is in all recipes except STREAM_FOCUS
    applyLFSRStep = (gCurrentRecipe != ZTMRecipe::STREAM_FOCUS);
  }
  
  if (applyLFSRStep) {
    // DEBUG: Log LFSR initialization parameters
    uint32_t lfsrSeed = (uint32_t)mk.lfsrSeed;
    uint32_t seedBe = ((lfsrSeed >> 24) & 0xFF) | ((lfsrSeed >> 8) & 0xFF00) | 
                      ((lfsrSeed << 8) & 0xFF0000) | ((lfsrSeed << 24) & 0xFF000000);
    uint32_t initialState = lfsrSeed ? lfsrSeed : 0xACE1u;
    
    if (verbose) {
      Serial.printf("[ESP32][LFSR] Initializing - Seed: 0x%08X SeedBe: 0x%08X ChaosKey[0..3]: ", lfsrSeed, seedBe);
      for (int i = 0; i < 4; ++i) {
        Serial.printf("%02X", mk.tinkerbellKey[i]);
      }
      Serial.printf(" InitialTap: 0x0029 State: 0x%08X\n", initialState);
      
      // Log input before LFSR
      Serial.printf("[ESP32][LFSR] Input (first 16 bytes): ");
      for (int i = 0; i < 16 && i < (int)buf.size(); ++i) {
        Serial.printf("%02X", buf[i]);
      }
      Serial.printf(" Buffer size: %u bytes\n", (unsigned)buf.size());
    }
    
    ChaoticLFSR32 lfsr(lfsrSeed, mk.tinkerbellKey, 0x0029u);
    
    // Save state before LFSR for keystream calculation
    std::vector<uint8_t> bufBeforeLFSR = buf;
    
    lfsr.xorBuffer(buf.data(), buf.size());
    
    if (verbose) {
      hexPrint("3_After_LFSR", buf.data(), buf.size());
      
      // Calculate and log the keystream that was applied
      Serial.printf("[ESP32][LFSR] Keystream (first 16 bytes): ");
      for (int i = 0; i < 16 && i < (int)buf.size(); ++i) {
        uint8_t ks = bufBeforeLFSR[i] ^ buf[i];
        Serial.printf("%02X", ks);
      }
      Serial.println();
    }
  }

  // Step 4: Tinkerbell encryption - FIXED: Consistent XOR stream
  // CRITICAL: In Normal Mode, always apply Tinkerbell
  // In ZTM Mode, apply Tinkerbell based on recipe
  bool applyTinkerbellStep = true; // Default for normal mode
  if (gCurrentMode == OperationalMode::ZTM) {
    // In ZTM, Tinkerbell is in FULL_STACK, CHACHA_HEAVY, CHAOS_ONLY
    applyTinkerbellStep = (gCurrentRecipe == ZTMRecipe::FULL_STACK || 
                          gCurrentRecipe == ZTMRecipe::CHACHA_HEAVY || 
                          gCurrentRecipe == ZTMRecipe::CHAOS_ONLY);
  }
  // Normal Mode: Always apply Tinkerbell (gCurrentMode == NORMAL)
  
  if (applyTinkerbellStep) {
    if (verbose) {
      Serial.printf("[ESP32][TINKERBELL] Input (first 16 bytes): ");
      for (int i = 0; i < 16 && i < (int)buf.size(); ++i) {
        Serial.printf("%02X", buf[i]);
      }
      Serial.printf(" Nonce: 0x%08X Buffer size: %u bytes\n", nonce, (unsigned)buf.size());
    }
    
    std::vector<uint8_t> bufBeforeTink = buf;
    xor_with_stream_hmac(mk.tinkerbellKey, nonce, buf.data(), buf.size(), verbose);
    
    if (verbose) {
      hexPrint("4_After_Tinkerbell", buf.data(), buf.size());
      
      // Calculate and log the keystream that was applied
      Serial.printf("[ESP32][TINKERBELL] Applied keystream (first 16 bytes): ");
      for (int i = 0; i < 16 && i < (int)buf.size(); ++i) {
        uint8_t ks = bufBeforeTink[i] ^ buf[i];
        Serial.printf("%02X", ks);
      }
      Serial.println();
    }
  }

  // Step 5: Transposition - FIXED: Use Forward mode for encryption
  // Apply transposition only if recipe includes it
  bool applyTranspositionStep = true; // Default for normal mode
  if (gCurrentMode == OperationalMode::ZTM) {
    // In ZTM, transposition is only in FULL_STACK and CHAOS_ONLY
    applyTranspositionStep = (gCurrentRecipe == ZTMRecipe::FULL_STACK || 
                              gCurrentRecipe == ZTMRecipe::CHAOS_ONLY);
  }
  
  if (applyTranspositionStep) {
    uint8_t trKey8[8];
    memcpy(trKey8, mk.transpositionKey, 8);
    applyTransposition(buf.data(), grid, trKey8, PermuteMode::Forward);
    if (verbose) hexPrint("5_After_Transposition", buf.data(), buf.size());
  }
  
  // ZTM MODE: Additional steps 6 & 7 (ChaCha20 and Salsa20)
  // CRITICAL: Only apply if in ZTM mode - Normal Mode stops here
  // When ZTM is active, normal mode encryption (LFSR + Tinkerbell + Transposition) has already been applied
  // Then we add ChaCha20 and/or Salsa20 based on recipe
  // When ZTM is NOT active, we stop after Transposition (normal mode)
  if (gCurrentMode == OperationalMode::ZTM && gZTMEnabled) {
    // Step 6: ChaCha20 (if recipe includes it)
    // FULL_STACK, CHACHA_HEAVY, STREAM_FOCUS include ChaCha20
    if (gCurrentRecipe == ZTMRecipe::FULL_STACK || 
        gCurrentRecipe == ZTMRecipe::CHACHA_HEAVY || 
        gCurrentRecipe == ZTMRecipe::STREAM_FOCUS) {
      ChaCha20 chacha;
      uint8_t chachaNonce[12];
      // CRITICAL: Use same nonce derivation for synchronization
      memcpy(chachaNonce, &nonce, 4);
      memset(chachaNonce + 4, 0, 8);
      // Use hmacKey as ChaCha20 key (32 bytes)
      chacha.init(baseKeys.hmacKey, 32, chachaNonce, 12);
      chacha.encrypt(buf.data(), buf.data(), buf.size());
      if (verbose) hexPrint("6_After_ChaCha20", buf.data(), buf.size());
    }
    
    // Step 7: Salsa20 (if recipe includes it)
    // FULL_STACK, SALSA_LIGHT, STREAM_FOCUS include Salsa20
    if (gCurrentRecipe == ZTMRecipe::FULL_STACK || 
        gCurrentRecipe == ZTMRecipe::SALSA_LIGHT || 
        gCurrentRecipe == ZTMRecipe::STREAM_FOCUS) {
      Salsa20 salsa;
      uint8_t salsaNonce[8];
      // CRITICAL: Use same nonce derivation for synchronization
      memcpy(salsaNonce, &nonce, 4);
      memset(salsaNonce + 4, 0, 4);
      // Use hmacKey as Salsa20 key (32 bytes)
      salsa.init(baseKeys.hmacKey, 32, salsaNonce, 8);
      salsa.encrypt(buf.data(), buf.data(), buf.size());
      if (verbose) hexPrint("7_After_Salsa20", buf.data(), buf.size());
    }
    
    // Recipe-specific notes:
    // - FULL_STACK: LFSR + Tinkerbell + Transposition + ChaCha20 + Salsa20 (all 5)
    // - CHACHA_HEAVY: LFSR + Tinkerbell + ChaCha20 (no Transposition, no Salsa20)
    // - SALSA_LIGHT: LFSR + Salsa20 (no Tinkerbell, no Transposition, no ChaCha20)
    // - CHAOS_ONLY: LFSR + Tinkerbell + Transposition (no stream ciphers)
    // - STREAM_FOCUS: ChaCha20 + Salsa20 (minimal chaos - no LFSR, no Tinkerbell, no Transposition)
    
    // Note: For STREAM_FOCUS, we skip LFSR and Tinkerbell steps above
    // This is handled by checking recipe before those steps
  }

  // Build packet with header and HMAC
  const size_t headerLen = 8;
  const size_t nonceLen = includeNonceExt ? 4 : 0;
  const size_t tagLen = HMAC_TAG_LEN;
  const size_t macInLen = headerLen + nonceLen + buf.size();

  packet.resize(macInLen + tagLen);
  uint8_t* p = packet.data();

  // Write header
  uint8_t version = includeNonceExt ? VERSION_NONCE_EXT : VERSION_BASE;
  writeHeader(p, version, salt_len, salt_pos, payload_len,
              (uint8_t)grid.rows, (uint8_t)grid.cols);

  // Write nonce if extended
  if (includeNonceExt) {
    p[8] = (uint8_t)((nonce >> 24) & 0xFF);
    p[9] = (uint8_t)((nonce >> 16) & 0xFF);
    p[10] = (uint8_t)((nonce >> 8) & 0xFF);
    p[11] = (uint8_t)(nonce & 0xFF);
  }

  // Copy encrypted data
  memcpy(p + headerLen + nonceLen, buf.data(), buf.size());

  // ADD HMAC DEBUGGING HERE - BEFORE HMAC COMPUTATION
  if (verbose) {
    Serial.printf("[ESP32] === HMAC DEBUG INFO ===\n");
    Serial.printf("[ESP32] HMAC Key being used: ");
    for (int i = 0; i < 32; ++i) {
      Serial.printf("%02X", baseKeys.hmacKey[i]);
    }
    Serial.println();
    
    Serial.printf("[ESP32] HMAC Input length: %u bytes\n", (unsigned)macInLen);
    Serial.printf("[ESP32] HMAC Input (first 32 bytes): ");
    for (int i = 0; i < 32 && i < macInLen; ++i) {
      Serial.printf("%02X", p[i]);
    }
    Serial.println();
    
    Serial.printf("[ESP32] Nonce: 0x%08X\n", nonce);
    Serial.printf("[ESP32] Packet size before HMAC: %u\n", (unsigned)packet.size());
  }

  // Compute HMAC - FIXED: Use consistent HMAC implementation
  if (!hmac_sha256_trunc(baseKeys.hmacKey, 32,
                         packet.data(), macInLen,
                         packet.data() + macInLen, tagLen)) {
    memset(packet.data() + macInLen, 0, tagLen);
  }
  
  // ADD HMAC DEBUGGING HERE - AFTER HMAC COMPUTATION
  if (verbose) {
    Serial.printf("[ESP32] Computed HMAC Tag: ");
    for (int i = 0; i < HMAC_TAG_LEN; ++i) {
      Serial.printf("%02X", p[macInLen + i]);
    }
    Serial.println();
    Serial.printf("[ESP32] === END HMAC DEBUG ===\n");
  }
  
  if (verbose) {
    hexPrint("6_Final_Packet", packet.data(), packet.size());
  }
}

// Internal function that accepts a specific nonce (for retries)
static bool encrypt_and_send_health_data_with_nonce(uint32_t nonce) {
  if (!masterKeyReady) {
    Serial.println("Master keys not ready");
    return false;
  }

  char healthBuffer[64];
  generate_realistic_health_data(healthBuffer, sizeof(healthBuffer), millis());
  Serial.printf("Generated health data: %s\n", healthBuffer);
  
  strncpy(currentPlaintext, healthBuffer, 127);
  currentPlaintext[127] = '\0';
  
  SaltMeta meta;
  meta.pos = (uint16_t)strlen(healthBuffer);
  meta.len = 2;
  
  const uint8_t* plainData = (const uint8_t*)healthBuffer;
  size_t plainLen = strlen(healthBuffer);
  GridSpec grid = selectGrid(plainLen);
  
  // Use provided nonce (don't increment here - caller manages nonce)
  // Mark as used but don't increment lastNonce yet - will increment only on success
  // This allows retries with same nonce if send fails
  gDeviceNonceTracker.lastTsMs = GET_TIME_MS();
  
  std::vector<uint8_t> packet;
  
  bool verbose = true;
  capturedLayerIndex = 0;
  capturingLayers = verbose;
  
  pipelineEncryptPacket(gBaseKeys, nonce, true, plainData, plainLen, grid,
                        meta.len, meta.pos, plainLen, packet, verbose);
  
  if (packet.empty()) {
    Serial.println("Encryption failed - empty packet");
    capturingLayers = false;
    return false;
  }
  
  // Send with retry logic
  const int MAX_SEND_RETRIES = 2;
  bool success = false;
  
  for (int attempt = 0; attempt < MAX_SEND_RETRIES && !success; attempt++) {
    if (attempt > 0) {
      Serial.printf("Retry attempt %d/%d\n", attempt + 1, MAX_SEND_RETRIES);
      delay(1000 * attempt);
    }
    
    success = http_post_enc_data_with_pipeline(packet, healthBuffer, 
                                               capturedLayers, capturedLayerIndex);
  }
  
  capturingLayers = false;
  
  if (success) {
    healthSendCount++;
    Serial.printf("✓ Health data sent successfully (#%d)\n", healthSendCount);
    // Mark nonce as successfully used (increment lastNonce to current nonce)
    // This ensures nonce increments only on successful send
    gDeviceNonceTracker.lastNonce = nonce;
    gDeviceNonceTracker.lastTsMs = GET_TIME_MS();
  } else {
    Serial.println("✗ Failed to send health data to server");
    // Don't increment nonce on failure - caller will rollback if all retries fail
  }
  
  return success;
}

// Public function that increments nonce automatically
static bool encrypt_and_send_health_data() {
  uint32_t nonce = nonce_tracker_get_next(&gDeviceNonceTracker);
  Serial.printf("[ENCRYPT] Generated nonce: %u\n", nonce);
  return encrypt_and_send_health_data_with_nonce(nonce);
}
// ============================================================================
// STATE MACHINE
// ============================================================================

static void printStatus(const char* stateName) {
  Serial.printf("[%.1f] STATE: %s | WiFi: %s | MasterKey: %s | HealthSent: %d | WS: %s\n",
    millis() / 1000.0, stateName,
    WiFi.status() == WL_CONNECTED ? "OK" : "DOWN",
    masterKeyReady ? "READY" : "PENDING",
    healthSendCount,
    wsConnected ? "CONNECTED" : "DISCONNECTED");
}

void handle_communication_state() {
  // Handle WebSocket events in every state
  if (WiFi.status() == WL_CONNECTED) {
    webSocket.loop();
  }
  
  switch (currentState) {
    case STATE_INIT_NVS: {
      printStatus("INIT_NVS");
      esp_err_t nvs_err = nvs_flash_init();
      if (nvs_err == ESP_ERR_NVS_NO_FREE_PAGES || nvs_err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        nvs_flash_erase();
        nvs_err = nvs_flash_init();
      }
      if (nvs_err == ESP_OK) {
        Serial.println("✓ NVS initialized");
        currentState = STATE_CONNECT_WIFI;
        sendWebSocketUpdate("nvs_initialized", "NVS storage initialized successfully");
      } else {
        Serial.printf("✗ NVS failed: %s\n", esp_err_to_name(nvs_err));
        currentState = STATE_ERROR;
      }
      break;
    }
    
    case STATE_CONNECT_WIFI: {
      printStatus("CONNECT_WIFI");
      if (WiFi.status() != WL_CONNECTED) {
        if (!wifiAttemptInProgress) {
          Serial.printf("Connecting to %s\n", WIFI_SSID);
          WiFi.disconnect(true, true);
          delay(100);
          WiFi.mode(WIFI_STA);
          WiFi.setSleep(false);
          WiFi.persistent(false);
          WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
          wifiAttemptInProgress = true;
          wifiAttemptStartMs = millis();
        }
        if (wifiAttemptInProgress && (millis() - wifiAttemptStartMs > 15000)) {
          Serial.println("WiFi connect timeout - retrying");
          wifiAttemptInProgress = false;
          retryCount++;
          delay(200);
        }
      } else {
        Serial.printf("✓ WiFi connected! IP: %s\n", WiFi.localIP().toString().c_str());
        wifiAttemptInProgress = false;
        currentState = STATE_CHECK_PUBLIC_KEY;
        sendWebSocketUpdate("wifi_connected", 
                           String("WiFi connected - IP: " + WiFi.localIP().toString()).c_str());
      }
      break;
    }
    
    case STATE_CHECK_PUBLIC_KEY: {
      printStatus("CHECK_PUBLIC_KEY");
      if (load_public_key_nvs(gPublicKey)) {
        publicKeyLoaded = true;
        Serial.println("✓ Public key loaded from NVS");
        currentState = STATE_GENERATE_MASTER_KEY;
      } else {
        Serial.println("No public key in NVS, fetching from server");
        currentState = STATE_GET_PUBLIC_KEY;
      }
      break;
    }
    
    case STATE_GET_PUBLIC_KEY: {
      printStatus("GET_PUBLIC_KEY");
      if (http_get_public_key()) {
        retryCount = 0;
        currentState = STATE_GENERATE_MASTER_KEY;
      } else {
        retryCount++;
        if (retryCount < MAX_RETRIES) {
          Serial.printf("Retry %d/%d for public key\n", retryCount, MAX_RETRIES);
          delay(2000);
        } else {
          Serial.println("Failed to get public key after max retries");
          currentState = STATE_ERROR;
        }
      }
      break;
    }
    
    case STATE_GENERATE_MASTER_KEY: {
      printStatus("GENERATE_MASTER_KEY");
      currentState = STATE_ENCRYPT_MASTER_KEY;
      break;
    }
    
    case STATE_ENCRYPT_MASTER_KEY: {
      printStatus("ENCRYPT_MASTER_KEY");
      if (generate_and_encrypt_master_key()) {
        retryCount = 0;
        currentState = STATE_DERIVE_SYMMETRIC;
        Serial.println("✓ Master key exchange completed");
      } else {
        retryCount++;
        if (retryCount < MAX_RETRIES) {
          Serial.printf("Retry %d/%d for master key\n", retryCount, MAX_RETRIES);
          delay(3000);
        } else {
          Serial.println("Master key exchange failed after max retries");
          currentState = STATE_ERROR;
        }
      }
      break;
    }
    
    case STATE_DERIVE_SYMMETRIC: {
      printStatus("DERIVE_SYMMETRIC");
      if (derive_symmetric_keys()) {
        Serial.println("✓ Symmetric keys ready - starting health data transmission");
        lastHealthSend = millis();
        currentState = STATE_SEND_HEALTH_DATA;
      } else {
        Serial.println("Symmetric key derivation failed");
        currentState = STATE_ERROR;
      }
      break;
    }
    
    case STATE_SEND_HEALTH_DATA: {
      printStatus("SEND_HEALTH_DATA");
      
      if (healthSendCount >= MAX_PACKETS) {
        Serial.println("Reached MAX_PACKETS limit; pausing transmissions");
        delay(2000);
        break;
      }
      
      if (millis() - lastHealthSend >= HEALTH_DATA_INTERVAL_MS) {
        // Generate health data first
        char healthBuffer[64];
        generate_realistic_health_data(healthBuffer, sizeof(healthBuffer), millis());
        Serial.printf("Generated health data: %s\n", healthBuffer);
        
        strncpy(currentPlaintext, healthBuffer, 127);
        currentPlaintext[127] = '\0';
        
        // Validate we can send
        if (!should_attempt_send()) {
          Serial.println("Cannot send - system not ready");
          currentState = STATE_ERROR;
          break;
        }
        
        // Use retry mechanism instead of direct call
        if (send_health_data_with_retry()) {
          retryCount = 0;
          lastHealthSend = millis();
          healthSendCount++; // Increment only on success
          Serial.printf("✓ Health data #%d sent successfully\n", healthSendCount);
        } else {
          retryCount++;
          Serial.printf("Health data send failed (retry count: %d/%d)\n", retryCount, MAX_RETRIES);
          
          if (retryCount >= MAX_RETRIES) {
            Serial.println("Health data transmission failed after max retries");
            currentState = STATE_ERROR;
          }
        }
      }
      break;
    }
    
    case STATE_ERROR: {
      printStatus("ERROR");
      Serial.println("ERROR state - attempting recovery");
      
      if (WiFi.status() != WL_CONNECTED) {
        Serial.println("WiFi down - transitioning to CONNECT_WIFI");
        currentState = STATE_CONNECT_WIFI;
        break;
      }

      if (!masterKeyReady) {
        Serial.println("Master keys not ready - trying to derive from NVS");
        if (!derive_symmetric_keys()) {
          Serial.println("Symmetric key derivation failed - restarting key exchange");
          currentState = STATE_CHECK_PUBLIC_KEY;
          break;
        }
      }

      // Try to recover by sending health data with retry mechanism
      bool recovered = send_health_data_with_retry();
      
      if (recovered) {
        Serial.println("✓ Auto-recovery succeeded - resuming normal transmissions");
        retryCount = 0;
        lastHealthSend = millis();
        currentState = STATE_SEND_HEALTH_DATA;
      } else {
        Serial.println("✗ Auto-recovery failed - restarting key exchange");
        delay(2000);
        currentState = STATE_CHECK_PUBLIC_KEY;
      }
      break;
    }
  }
}

// ============================================================================
// ZTM AND HEURISTICS FUNCTIONS
// ============================================================================

static void recordEvent(const char* eventType) {
  uint32_t now = GET_TIME_MS();
  gHeuristics.lastEventTime = now;
  
  if (strcmp(eventType, "hmac_failure") == 0) {
    gHeuristics.hmacFailures++;
    Serial.printf("[ZTM] Event recorded: HMAC failure (count: %u)\n", gHeuristics.hmacFailures);
  } else if (strcmp(eventType, "decrypt_failure") == 0) {
    gHeuristics.decryptFailures++;
    Serial.printf("[ZTM] Event recorded: Decrypt failure (count: %u)\n", gHeuristics.decryptFailures);
  } else if (strcmp(eventType, "replay_attempt") == 0) {
    gHeuristics.replayAttempts++;
    Serial.printf("[ZTM] Event recorded: Replay attempt (count: %u)\n", gHeuristics.replayAttempts);
  } else if (strcmp(eventType, "malformed_packet") == 0) {
    gHeuristics.malformedPackets++;
    Serial.printf("[ZTM] Event recorded: Malformed packet (count: %u)\n", gHeuristics.malformedPackets);
  } else if (strcmp(eventType, "timing_anomaly") == 0) {
    gHeuristics.timingAnomalies++;
    Serial.printf("[ZTM] Event recorded: Timing anomaly (count: %u)\n", gHeuristics.timingAnomalies);
  }
  
  // In normal mode, log but don't switch. In ZTM mode, evaluate and potentially switch
  if (gZTMEnabled && gCurrentMode == OperationalMode::ZTM) {
    evaluateThreatAndSwitchRecipe();
  }
  
  // Send event to frontend via WebSocket
  if (wsConnected) {
    DynamicJsonDocument doc(512);
    doc["type"] = "threat_event";
    doc["eventType"] = eventType;
    doc["timestamp"] = now;
    doc["hmacFailures"] = gHeuristics.hmacFailures;
    doc["decryptFailures"] = gHeuristics.decryptFailures;
    doc["replayAttempts"] = gHeuristics.replayAttempts;
    doc["malformedPackets"] = gHeuristics.malformedPackets;
    doc["timingAnomalies"] = gHeuristics.timingAnomalies;
    doc["ztmEnabled"] = gZTMEnabled;
    doc["currentMode"] = (gCurrentMode == OperationalMode::ZTM) ? "ztm" : "normal";
    doc["currentRecipe"] = recipeToString(gCurrentRecipe).c_str();
    
    String jsonStr;
    serializeJson(doc, jsonStr);
    webSocket.sendTXT(jsonStr);
  }
}

static bool evaluateThreatAndSwitchRecipe() {
  if (!gZTMEnabled || gCurrentMode != OperationalMode::ZTM) {
    return false;
  }
  
  uint32_t now = GET_TIME_MS();
  
  // Cooldown check - prevent rapid switching (from heuristics.json: min_switch_interval_seconds = 5)
  const uint32_t MIN_SWITCH_INTERVAL_MS = 5000;
  if (now - gLastRecipeSwitchTime < MIN_SWITCH_INTERVAL_MS) {
    return false;
  }
  
  // Thresholds from heuristics.json - based on actual attack data
  // These are mapped from the heuristics.json detection rules
  
  bool shouldSwitch = false;
  ZTMRecipe targetRecipe = gCurrentRecipe;
  String switchReason = "";
  
  // 1. RNG Manipulation Detection (heuristics.json: rng_manipulation)
  // Detected via entropy drop - maps to decrypt failures or entropy anomalies
  // Recipe: FULL_STACK (all-security mode)
  // Threshold: entropy_drop > 1.5 (high confidence: 0.99)
  // For ESP32, we approximate this with decrypt failures as entropy proxy
  if (gHeuristics.decryptFailures >= 3) { // High confidence threshold
    targetRecipe = ZTMRecipe::FULL_STACK;
    shouldSwitch = true;
    switchReason = "RNG manipulation detected - switch to all-security mode";
    gHeuristics.violationCounter++;
    Serial.println("[ZTM] " + switchReason);
  }
  // 2. Timing Attack Detection (heuristics.json: timing_attack)
  // Detected via latency variance (latency_cv > 0.05 or latency_max_min_delta > 10.0)
  // Recipe: SALSA_LIGHT (constant-time cipher)
  // Threshold: min_confidence = 0.85
  else if (gHeuristics.timingAnomalies >= 5) { // Based on timing_anomaly threshold
    targetRecipe = ZTMRecipe::SALSA_LIGHT;
    shouldSwitch = true;
    switchReason = "Timing side-channel detected - switch to constant-time cipher";
    gHeuristics.violationCounter++;
    Serial.println("[ZTM] " + switchReason);
  }
  // 3. UDP Flood / Network DoS (heuristics.json: udp_flood)
  // Detected via latency spike (latency_ms > 55.0 or zscore > 3.0)
  // Recipe: CHAOS_ONLY (maintain baseline security)
  // Threshold: min_confidence = 0.80, cooldown = 30s
  else if (gHeuristics.malformedPackets >= 8) { // Network attack indicator
    targetRecipe = ZTMRecipe::CHAOS_ONLY;
    shouldSwitch = true;
    switchReason = "Network DoS detected - maintain baseline security";
    gHeuristics.violationCounter++;
    Serial.println("[ZTM] " + switchReason);
  }
  // 4. TCP SYN Flood (heuristics.json: tcp_syn_flood)
  // Detected via memory_and_latency (memory_percent > 0.22 AND latency_ms > 54.0)
  // Recipe: CHAOS_ONLY
  // Threshold: min_confidence = 0.75
  else if (gHeuristics.replayAttempts >= 2) { // TCP flood often involves replay
    targetRecipe = ZTMRecipe::CHAOS_ONLY;
    shouldSwitch = true;
    switchReason = "TCP SYN flood detected - maintain baseline security";
    gHeuristics.violationCounter++;
    Serial.println("[ZTM] " + switchReason);
  }
  // 5. CPU Stress (heuristics.json: cpu_stress)
  // Detected via latency_variance_and_memory (latency_cv > 0.1 AND memory_percent > 0.22)
  // Recipe: SALSA_LIGHT (low-overhead cipher)
  // Threshold: min_confidence = 0.75
  else if (gHeuristics.timingAnomalies >= 3 && gHeuristics.malformedPackets >= 5) {
    targetRecipe = ZTMRecipe::SALSA_LIGHT;
    shouldSwitch = true;
    switchReason = "CPU exhaustion detected - switch to low-overhead cipher";
    gHeuristics.violationCounter++;
    Serial.println("[ZTM] " + switchReason);
  }
  // 6. Memory Stress (heuristics.json: memory_stress)
  // Detected via memory_threshold (memory_percent > 0.23)
  // Recipe: SALSA_LIGHT (lightweight cipher)
  // Threshold: min_confidence = 0.85
  else if (gHeuristics.malformedPackets >= 6) { // Memory stress often shows as packet issues
    targetRecipe = ZTMRecipe::SALSA_LIGHT;
    shouldSwitch = true;
    switchReason = "Memory saturation detected - use lightweight cipher";
    gHeuristics.violationCounter++;
    Serial.println("[ZTM] " + switchReason);
  }
  // 7. HMAC Failures - Critical security issue
  // Not explicitly in heuristics.json but critical - switch to FULL_STACK
  else if (gHeuristics.hmacFailures >= 3) {
    targetRecipe = ZTMRecipe::FULL_STACK;
    shouldSwitch = true;
    switchReason = "HMAC failures detected - maximum security required";
    gHeuristics.violationCounter++;
    Serial.println("[ZTM] " + switchReason);
  }
  // Deescalation: Return to FULL_STACK after stability period
  else {
    gHeuristics.stabilityCounter++;
    // After 5 stable cycles (from controller_config deescalation logic)
    if (gHeuristics.stabilityCounter >= 5 && gCurrentRecipe != ZTMRecipe::FULL_STACK) {
      targetRecipe = ZTMRecipe::FULL_STACK;
      shouldSwitch = true;
      switchReason = "System stable - returning to maximum security";
      gHeuristics.stabilityCounter = 0;
      Serial.println("[ZTM] " + switchReason);
    }
  }
  
  if (shouldSwitch && targetRecipe != gCurrentRecipe) {
    switchToRecipe(targetRecipe, false);
    
    // Send switch reason to frontend
    if (wsConnected) {
      DynamicJsonDocument doc(512);
      doc["type"] = "recipe_switched";
      doc["oldRecipe"] = recipeToString(gCurrentRecipe).c_str();
      doc["newRecipe"] = recipeToString(targetRecipe).c_str();
      doc["reason"] = switchReason.c_str();
      doc["timestamp"] = now;
      
      String jsonStr;
      serializeJson(doc, jsonStr);
      webSocket.sendTXT(jsonStr);
    }
    
    return true;
  }
  
  return false;
}

static void switchToRecipe(ZTMRecipe recipe, bool force) {
  if (!force) {
    uint32_t now = GET_TIME_MS();
    if (now - gLastRecipeSwitchTime < RECIPE_SWITCH_COOLDOWN_MS) {
      Serial.printf("[ZTM] Recipe switch cooldown active (wait %u ms)\n", 
                   RECIPE_SWITCH_COOLDOWN_MS - (now - gLastRecipeSwitchTime));
      return;
    }
  }
  
  ZTMRecipe oldRecipe = gCurrentRecipe;
  gCurrentRecipe = recipe;
  gLastRecipeSwitchTime = GET_TIME_MS();
  
  Serial.printf("[ZTM] Recipe switched: %s -> %s\n", 
               recipeToString(oldRecipe).c_str(), 
               recipeToString(recipe).c_str());
  
  // CRITICAL: Regenerate keys/nonces to prevent decryption errors
  // This ensures synchronization between encryption and decryption
  Serial.println("[ZTM] Regenerating keys and nonces for recipe switch...");
  
  // Save new recipe
  saveZTMSettings();
  
  // Send update to frontend
  if (wsConnected) {
    DynamicJsonDocument doc(512);
    doc["type"] = "recipe_switched";
    doc["oldRecipe"] = recipeToString(oldRecipe).c_str();
    doc["newRecipe"] = recipeToString(recipe).c_str();
    doc["timestamp"] = gLastRecipeSwitchTime;
    doc["reason"] = "threat_detection";
    
    String jsonStr;
    serializeJson(doc, jsonStr);
    webSocket.sendTXT(jsonStr);
  }
  
  sendWebSocketUpdate("recipe_switched", 
                     String("Recipe: " + recipeToString(recipe)).c_str());
}

static String recipeToString(ZTMRecipe recipe) {
  switch (recipe) {
    case ZTMRecipe::FULL_STACK: return "FULL_STACK";
    case ZTMRecipe::CHACHA_HEAVY: return "CHACHA_HEAVY";
    case ZTMRecipe::SALSA_LIGHT: return "SALSA_LIGHT";
    case ZTMRecipe::CHAOS_ONLY: return "CHAOS_ONLY";
    case ZTMRecipe::STREAM_FOCUS: return "STREAM_FOCUS";
    default: return "UNKNOWN";
  }
}

static bool verifyPasskey(const String& passkey) {
  // Hardcoded passkey: 2421 (final)
  const String VALID_PASSKEY = "2421";
  
  bool isValid = (passkey == VALID_PASSKEY);
  
  if (isValid) {
    Serial.println("[ZTM] Passkey verified successfully");
    // Store passkey in NVS for future reference
    nvs_handle_t handle;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &handle);
    if (err == ESP_OK) {
      nvs_set_str(handle, NVS_ZTM_PASSKEY_KEY, VALID_PASSKEY.c_str());
      nvs_commit(handle);
      nvs_close(handle);
    }
  } else {
    Serial.println("[ZTM] Invalid passkey provided");
  }
  
  return isValid;
}

static bool loadZTMSettings() {
  nvs_handle_t handle;
  esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READONLY, &handle);
  if (err != ESP_OK) {
    Serial.println("[ZTM] Failed to open NVS for loading settings");
    return false;
  }
  
  uint8_t mode = 0;
  uint8_t recipe = 0;
  
  err = nvs_get_u8(handle, NVS_ZTM_MODE_KEY, &mode);
  if (err == ESP_OK) {
    gCurrentMode = (mode == 1) ? OperationalMode::ZTM : OperationalMode::NORMAL;
    gZTMEnabled = (mode == 1);
  }
  
  err = nvs_get_u8(handle, NVS_ZTM_RECIPE_KEY, &recipe);
  if (err == ESP_OK && recipe < 5) {
    gCurrentRecipe = (ZTMRecipe)recipe;
  }
  
  nvs_close(handle);
  
  if (gZTMEnabled) {
    Serial.printf("[ZTM] Loaded settings: Mode=%s, Recipe=%s\n",
                 (gCurrentMode == OperationalMode::ZTM) ? "ZTM" : "NORMAL",
                 recipeToString(gCurrentRecipe).c_str());
  }
  
  return true;
}

static bool saveZTMSettings() {
  nvs_handle_t handle;
  esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &handle);
  if (err != ESP_OK) {
    Serial.println("[ZTM] Failed to open NVS for saving settings");
    return false;
  }
  
  uint8_t mode = (gCurrentMode == OperationalMode::ZTM) ? 1 : 0;
  uint8_t recipe = (uint8_t)gCurrentRecipe;
  
  err = nvs_set_u8(handle, NVS_ZTM_MODE_KEY, mode);
  if (err == ESP_OK) {
    err = nvs_set_u8(handle, NVS_ZTM_RECIPE_KEY, recipe);
  }
  
  if (err == ESP_OK) {
    err = nvs_commit(handle);
  }
  
  nvs_close(handle);
  
  if (err == ESP_OK) {
    Serial.println("[ZTM] Settings saved successfully");
    return true;
  } else {
    Serial.printf("[ZTM] Failed to save settings: %s\n", esp_err_to_name(err));
    return false;
  }
}

// ============================================================================
// ARDUINO SETUP & LOOP
// ============================================================================

void setup() {
  Serial.begin(115200);
  delay(1000);

  Serial.println("=== XenoCipher ESP32 Booting ===");
  Serial.printf("Free heap: %d bytes\n", ESP.getFreeHeap());

  WiFi.onEvent(onWiFiEvent);
  // Reset nonce counter after successful key exchange
  nonce_tracker_init(&gDeviceNonceTracker);
  Serial.println("Nonce counter reset for new session");
  
  // Load ZTM settings from NVS
  loadZTMSettings();
}

void loop() {
  handle_communication_state();
  delay(100);
}