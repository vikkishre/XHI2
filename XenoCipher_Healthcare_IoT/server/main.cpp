#include <crow.h>
#include <pqxx/pqxx>
#include <mbedtls/md.h>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <regex>
#include <ctime>
#include <thread>
#include <atomic>
#include <chrono>
#include <unordered_set>
#include <unordered_map>
#include <nlohmann/json.hpp>

// Custom cryptographic libraries
#include "../lib/NTRU/include/ntru.h"
#include "../lib/common/common.h"
#include "../lib/CryptoKDF/include/crypto_kdf.h"
#include "../lib/HMAC/include/hmac.h"
#include "../lib/LFSR/include/lfsr.h"
#include "../lib/Tinkerbell/include/tinkerbell.h"
#include "../lib/Transposition/include/transposition.h"

// ZTM Handlers
#include "api/ztm_handlers.h"

// Event bus for WebSocket communications
class EventBus {
private:
    static std::unordered_set<crow::websocket::connection*> clients;
    static std::mutex mtx;
    static std::unordered_map<crow::websocket::connection*, std::string> clientSessions;

public:
    static void addClient(crow::websocket::connection* conn, const std::string& sessionId = "") {
        std::lock_guard<std::mutex> lock(mtx);
        clients.insert(conn);
        if (!sessionId.empty()) {
            clientSessions[conn] = sessionId;
        }
    }

    static void removeClient(crow::websocket::connection* conn) {
        std::lock_guard<std::mutex> lock(mtx);
        clients.erase(conn);
        clientSessions.erase(conn);
    }

    static void broadcast(const nlohmann::json& message) {
        std::lock_guard<std::mutex> lock(mtx);
        std::string msgStr = message.dump();
        for (auto client : clients) {
            client->send_text(msgStr);
        }
    }

    static void sendToClient(crow::websocket::connection* conn, const nlohmann::json& message) {
        std::lock_guard<std::mutex> lock(mtx);
        conn->send_text(message.dump());
    }

    static size_t getClientCount() {
        std::lock_guard<std::mutex> lock(mtx);
        return clients.size();
    }

    static std::string getClientSession(crow::websocket::connection* conn) {
        std::lock_guard<std::mutex> lock(mtx);
        auto it = clientSessions.find(conn);
        return it != clientSessions.end() ? it->second : "";
    }
};

std::unordered_set<crow::websocket::connection*> EventBus::clients;
std::mutex EventBus::mtx;
std::unordered_map<crow::websocket::connection*, std::string> EventBus::clientSessions;

// Configuration
#define HMAC_TAG_LEN 16
#define GET_TIME_MS() (std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count())

// Global state
std::vector<uint8_t> gMasterKey;

// Structures
struct SaltMeta {
    uint16_t pos;
    uint8_t len;
};

// Pipeline intermediates storage
struct PipelineIntermediates {
    std::string afterSalt;
    std::string afterLFSR;
    std::string afterTinkerbell;
    std::string afterTransposition;
    std::string afterDepad;
};

// NTRU Server
class NTRUServer {
public:
    NTRUServer() : ntru() {
        ntru.generate_keys(keyPair);
    }

    std::vector<uint8_t> getPublicKey() const {
        std::vector<uint8_t> bytes;
        NTRU::poly_to_bytes16(keyPair.h, bytes);
        return bytes;
    }

    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& encKey) {
        Poly e, m;
        NTRU::bytes_to_poly16(encKey, e);
        ntru.decrypt(e, keyPair.f, m);
        std::vector<uint8_t> bytes;
        NTRU::poly_to_bytes(m, bytes, 32);
        return bytes;
    }

private:
    NTRU ntru;
    NTRUKeyPair keyPair;
};

// Security monitoring
struct SecurityMetrics {
    uint32_t decrypt_failures;
    uint32_t hmac_failures;
    uint32_t replay_attempts;
    uint32_t requests_per_minute;
};

struct AdaptiveMonitor {
    SecurityMetrics metrics;
    uint64_t lastSecurityBroadcast;
};

static AdaptiveMonitor gAdaptiveMonitor;

struct NonceTracker { 
    std::unordered_set<uint32_t> used; 
    std::mutex mtx;
    uint64_t startupTime;
};

static NonceTracker gNonceTracker;

// Utility functions
std::vector<uint8_t> hexToBytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
    SecurityMetrics metrics;
    uint64_t lastSecurityBroadcast;
};

static AdaptiveMonitor gAdaptiveMonitor;

struct NonceTracker { 
    std::unordered_set<uint32_t> used; 
    std::mutex mtx;
    uint64_t startupTime;
};

static NonceTracker gNonceTracker;

// Utility functions
std::vector<uint8_t> hexToBytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = (uint8_t)std::stoul(byteString, nullptr, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

std::string bytesToHex(const std::vector<uint8_t>& bytes) {
    std::stringstream ss;
    ss << std::hex << std::uppercase << std::setfill('0');
    for (uint8_t b : bytes) {
        ss << std::setw(2) << (int)b;
    }
    return ss.str();
}

std::string bytesToHex(const uint8_t* data, size_t len) {
    std::stringstream ss;
    ss << std::hex << std::uppercase << std::setfill('0');
    for (size_t i = 0; i < len; ++i) {
        ss << std::setw(2) << (int)data[i];
    }
    return ss.str();
}

void log_warn(const std::string& msg) {
    time_t now = time(nullptr);
    std::string dt = ctime(&now);
    dt.erase(dt.find_last_not_of("\n\r") + 1);
    std::cout << "[WARN] [" << dt << "] " << msg << std::endl;
}

bool isValidUTF8(const std::string& str) {
    for (size_t i = 0; i < str.length();) {
        unsigned char c = str[i];
        if (c <= 0x7F) {
            i++;
        } else if ((c & 0xE0) == 0xC0) {
            if (i + 1 >= str.length() || (str[i+1] & 0xC0) != 0x80) return false;
            i += 2;
        } else if ((c & 0xF0) == 0xE0) {
            if (i + 2 >= str.length() || (str[i+1] & 0xC0) != 0x80 || (str[i+2] & 0xC0) != 0x80) return false;
            i += 3;
        } else if ((c & 0xF8) == 0xF0) {
            if (i + 3 >= str.length() || (str[i+1] & 0xC0) != 0x80 || (str[i+2] & 0xC0) != 0x80 || (str[i+3] & 0xC0) != 0x80) return false;
            i += 4;
        } else {
            return false;
        }
    }
    return true;
}

std::string cleanUTF8(const std::string& str) {
    std::string result;
    for (size_t i = 0; i < str.length();) {
        unsigned char c = str[i];
        if (c <= 0x7F) {
            result += c;
            i++;
        } else if ((c & 0xE0) == 0xC0 && i + 1 < str.length()) {
            if ((str[i+1] & 0xC0) == 0x80) {
                result += str.substr(i, 2);
                i += 2;
            } else {
                i++;
            }
        } else if ((c & 0xF0) == 0xE0 && i + 2 < str.length()) {
            if ((str[i+1] & 0xC0) == 0x80 && (str[i+2] & 0xC0) == 0x80) {
                result += str.substr(i, 3);
                i += 3;
            } else {
                i++;
            }
        } else if ((c & 0xF8) == 0xF0 && i + 3 < str.length()) {
            if ((str[i+1] & 0xC0) == 0x80 && (str[i+2] & 0xC0) == 0x80 && (str[i+3] & 0xC0) == 0x80) {
                result += str.substr(i, 4);
                i += 4;
            } else {
                i++;
            }
        } else {
            i++;
        }
    }
    return result;
}

// Robust UTF-8 sanitization for JSON serialization
// Replaces invalid UTF-8 sequences with '?' to ensure JSON compatibility
std::string safeJsonString(const std::string& input) {
    if (input.empty()) {
        return "";
    }
    
    // First, validate if it's already valid UTF-8
    if (isValidUTF8(input)) {
        // Check for control characters that might cause JSON issues
        std::string result;
        result.reserve(input.length());
        for (unsigned char c : input) {
            // Keep printable ASCII and valid UTF-8 continuation bytes
            if (c >= 0x20 || c == '\t' || c == '\n' || c == '\r') {
                result += c;
            } else if (c < 0x20 && c != '\t' && c != '\n' && c != '\r') {
                // Replace control characters with '?'
                result += '?';
            } else {
                result += c;
            }
        }
        return result;
    }
    
    // If not valid UTF-8, clean it aggressively
    std::string cleaned = cleanUTF8(input);
    
    // Further sanitize: replace any remaining invalid bytes
    std::string result;
    result.reserve(cleaned.length());
    for (size_t i = 0; i < cleaned.length();) {
        unsigned char c = cleaned[i];
        if (c <= 0x7F) {
            // ASCII
            if (c >= 0x20 || c == '\t' || c == '\n' || c == '\r') {
                result += c;
            } else {
                result += '?';  // Replace control characters
            }
            i++;
        } else if ((c & 0xE0) == 0xC0 && i + 1 < cleaned.length()) {
            if ((cleaned[i+1] & 0xC0) == 0x80) {
                result += cleaned.substr(i, 2);
                i += 2;
            } else {
                result += '?';
                i++;
            }
        } else if ((c & 0xF0) == 0xE0 && i + 2 < cleaned.length()) {
            if ((cleaned[i+1] & 0xC0) == 0x80 && (cleaned[i+2] & 0xC0) == 0x80) {
                result += cleaned.substr(i, 3);
                i += 3;
            } else {
                result += '?';
                i++;
            }
        } else if ((c & 0xF8) == 0xF0 && i + 3 < cleaned.length()) {
            if ((cleaned[i+1] & 0xC0) == 0x80 && (cleaned[i+2] & 0xC0) == 0x80 && (cleaned[i+3] & 0xC0) == 0x80) {
                result += cleaned.substr(i, 4);
                i += 4;
            } else {
                result += '?';
                i++;
            }
        } else {
            // Invalid byte, replace with '?'
            result += '?';
            i++;
        }
    }
    
    // If result is still empty or all '?', return a descriptive message
    if (result.empty() || (result.length() > 0 && result.find_first_not_of('?') == std::string::npos)) {
        return "[CORRUPTED_DATA: Invalid UTF-8]";
    }
    
    return result;
}

void log_error(const std::string& msg) {
    time_t now = time(nullptr);
    std::string dt = ctime(&now);
    dt.erase(dt.find_last_not_of("\n\r") + 1);
    std::cerr << "[ERROR] [" << dt << "] " << msg << std::endl;
}

void log_info(const std::string& msg) {
    time_t now = time(nullptr);
    std::string dt = ctime(&now);
    dt.erase(dt.find_last_not_of("\n\r") + 1);
    std::cout << "[INFO] [" << dt << "] " << msg << std::endl;
}

void log_debug(const std::string& msg) {
    time_t now = time(nullptr);
    std::string dt = ctime(&now);
    dt.erase(dt.find_last_not_of("\n\r") + 1);
    std::cout << "[DEBUG] [" << dt << "] " << msg << std::endl;
}

// Adaptive monitoring functions
static void adaptive_monitor_init(AdaptiveMonitor* am) { 
    am->metrics = {0, 0, 0, 0}; 
    am->lastSecurityBroadcast = 0;
}

static void adaptive_monitor_update_request(AdaptiveMonitor* am) { 
    if (am) am->metrics.requests_per_minute++; 
}

static void adaptive_monitor_update_decrypt_failure(AdaptiveMonitor* am) { 
    if (am) am->metrics.decrypt_failures++; 
}

static void adaptive_monitor_update_hmac_failure(AdaptiveMonitor* am) { 
    if (am) am->metrics.hmac_failures++; 
}

static void adaptive_monitor_update_replay_attempt(AdaptiveMonitor* am) { 
    if (am) am->metrics.replay_attempts++; 
}

static void adaptive_monitor_reset_window(AdaptiveMonitor* am) { 
    if (am) am->metrics = {0, 0, 0, 0}; 
}

static const SecurityMetrics* adaptive_monitor_get_metrics(const AdaptiveMonitor* am) { 
    return &am->metrics; 
}

// Nonce tracking functions - FIXED VERSION
static void nonce_tracker_init(NonceTracker* nt) { 
    std::lock_guard<std::mutex> lock(nt->mtx);
    nt->used.clear(); 
    nt->startupTime = GET_TIME_MS();
    log_info("Nonce tracker initialized - all previous nonces cleared");
}

static bool nonce_tracker_validate(NonceTracker* nt, uint32_t n) { 
    std::lock_guard<std::mutex> lock(nt->mtx);
    
    // Allow nonce 1 for initial communication (ESP32 starts at 1)
    if (n == 1) {
        log_debug("Allowing initial nonce 1");
        return true;
    }
    
    // Check if nonce has been used
    if (nt->used.find(n) != nt->used.end()) {
        log_warn("Nonce " + std::to_string(n) + " already used - replay attack detected");
        return false;
    }
    
    return true;
}

static void nonce_tracker_mark_used(NonceTracker* nt, uint32_t n) { 
    std::lock_guard<std::mutex> lock(nt->mtx);
    
    if (n == 0) {
        return;
    }
    
    nt->used.insert(n); 
    log_debug("Marked nonce " + std::to_string(n) + " as used");
}

static void nonce_tracker_cleanup(NonceTracker* nt) {
    std::lock_guard<std::mutex> lock(nt->mtx);
    if (nt->used.size() > 1000) {
        auto it = nt->used.begin();
        std::advance(it, nt->used.size() - 500);
        nt->used.erase(nt->used.begin(), it);
        log_debug("Nonce tracker cleaned up, kept " + std::to_string(nt->used.size()) + " most recent nonces");
    }
}

// FIXED: Consistent Tinkerbell XOR stream implementation
static void xor_with_stream_hmac(const uint8_t key[16], uint32_t nonce, uint8_t* data, size_t len) {
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
        if (firstBlock) {
            std::ostringstream tinkDebug;
            tinkDebug << "[TINKERBELL] Generating keystream block - Nonce: 0x" 
                     << std::hex << std::uppercase << std::setfill('0') << std::setw(8) << nonce
                     << " Counter: " << (int)counter
                     << " (must start at 0)"
                     << " Key[0..3]: " << bytesToHex(key, 4);
            log_debug(tinkDebug.str());
            firstBlock = false;
        } else if (offset < len) {
            // Log when counter increments (for buffers > 32 bytes)
            std::ostringstream tinkCounterDebug;
            tinkCounterDebug << "[TINKERBELL] Counter incrementing to: " << (int)counter;
            log_debug(tinkCounterDebug.str());
        }
        
        hmac_sha256_full(key, 16, msg, sizeof(msg), block);
        
        // DEBUG: Log first 16 bytes of keystream block
        if (offset == 0) {
            std::ostringstream keystreamDebug;
            keystreamDebug << "[TINKERBELL] Keystream block[" << (int)counter << "] (first 16 bytes): " 
                          << bytesToHex(block, 16);
            log_debug(keystreamDebug.str());
        }
        
        size_t n = (len - offset) < sizeof(block) ? (len - offset) : sizeof(block);
        for (size_t i = 0; i < n; ++i) {
            data[offset + i] ^= block[i];
        }
        offset += n;
        counter++;
    }
}

std::vector<uint8_t> removeSalt(const std::vector<uint8_t>& salted, size_t saltedLen, const SaltMeta& meta) {
    if (meta.len == 0 || meta.pos > saltedLen) {
        return std::vector<uint8_t>(salted.begin(), salted.begin() + saltedLen);
    }
    
    std::vector<uint8_t> out(saltedLen - meta.len);
    std::copy(salted.begin(), salted.begin() + meta.pos, out.begin());
    std::copy(salted.begin() + meta.pos + meta.len, salted.begin() + saltedLen, out.begin() + meta.pos);
    return out;
}

// FIXED: Compatible decryption pipeline that matches ESP32 implementation
std::string pipelineDecryptPacketWithIntermediates(
    const DerivedKeys& baseKeys, 
    const std::vector<uint8_t>& packet, 
    size_t packetLen,
    PipelineIntermediates& intermediates) {
    
    adaptive_monitor_update_request(&gAdaptiveMonitor);
    
    if (packetLen < 8 + HMAC_TAG_LEN) {
        log_error("Packet too short: " + std::to_string(packetLen));
        adaptive_monitor_update_decrypt_failure(&gAdaptiveMonitor);
        return "";
    }

    // Parse header
    const uint8_t* packetData = packet.data();
    uint8_t version = packetData[0];
    bool hasNonce = (version & 0x80) != 0;
    size_t nonceLen = hasNonce ? 4 : 0;
    
    if (packetLen < 8 + nonceLen + HMAC_TAG_LEN) {
        log_error("Packet too short for nonce: " + std::to_string(packetLen));
        adaptive_monitor_update_decrypt_failure(&gAdaptiveMonitor);
        return "";
    }

    uint8_t saltLen = packetData[1];
    uint16_t saltPos = (packetData[2] | (packetData[3] << 8));
    uint16_t payloadLen = (packetData[4] | (packetData[5] << 8));
    uint8_t rows = packetData[6];
    uint8_t cols = packetData[7];
    GridSpec grid = {rows, cols};
    SaltMeta saltMeta = {saltPos, saltLen};

    // Extract nonce
    uint32_t nonce = 0;
    if (hasNonce) {
        nonce = (packetData[8] << 24) | (packetData[9] << 16) | (packetData[10] << 8) | packetData[11];
    }

    // Validate nonce - FIXED: Allow nonce 1 for initial communication
    // But don't mark as used yet - wait until after successful HMAC verification
    if (hasNonce && !nonce_tracker_validate(&gNonceTracker, nonce)) {
        adaptive_monitor_update_replay_attempt(&gAdaptiveMonitor);
        log_error("Replay attack detected! Nonce already used: " + std::to_string(nonce));
        
        // For nonce 1, allow it but warn
        if (nonce == 1) {
            log_warn("Nonce 1 detected - allowing for initial communication but this should be incremented");
        } else {
            return "";
        }
    }

    // Extract ciphertext and tag
    size_t ctStart = 8 + nonceLen;
    size_t ctLen = packetLen - ctStart - HMAC_TAG_LEN;
    std::vector<uint8_t> ct(packetData + ctStart, packetData + ctStart + ctLen);
    std::vector<uint8_t> tag(packetData + ctStart + ctLen, packetData + packetLen);

    std::ostringstream nonceLogStr;
    nonceLogStr << std::hex << std::uppercase << std::setfill('0') << std::setw(8) << nonce;
    log_debug("Header: ver=0x" + bytesToHex(&version, 1) +
             " saltLen=" + std::to_string(saltLen) +
             " saltPos=" + std::to_string(saltPos) +
             " payloadLen=" + std::to_string(payloadLen) +
             " rows=" + std::to_string(rows) +
             " cols=" + std::to_string(cols) +
             " nonce=0x" + nonceLogStr.str());

    // Derive message keys
    MessageKeys messageKeys;
    if (!deriveMessageKeys(baseKeys, nonce, messageKeys)) {
        log_error("Failed to derive message keys");
        return "";
    }

    // FIXED: Debug output for derived keys - format matches ESP32
    std::ostringstream seedStr, nonceStr;
    seedStr << std::hex << std::uppercase << std::setfill('0') << std::setw(8) << messageKeys.lfsrSeed;
    nonceStr << std::hex << std::uppercase << std::setfill('0') << std::setw(8) << nonce;
    log_debug("MsgKeys: lfsrSeed=0x" + seedStr.str() +
             " tnk[0..3]=" + bytesToHex(messageKeys.tinkerbellKey, 4) +
             " trn[0..3]=" + bytesToHex(messageKeys.transpositionKey, 4) +
             " (nonce=0x" + nonceStr.str() + ")");

    // Verify HMAC with detailed debugging
    const size_t headerLen = 8;
    const size_t inputLen = headerLen + nonceLen + ct.size();
    uint8_t tagCheck[HMAC_TAG_LEN];
    
    // HMAC debugging
    {
        std::ostringstream hk, tp, tc, hi;
        hk << std::hex << std::uppercase << std::setfill('0');
        tp << std::hex << std::uppercase << std::setfill('0');
        tc << std::hex << std::uppercase << std::setfill('0');
        hi << std::hex << std::uppercase << std::setfill('0');
        
        // Print first 16 bytes of HMAC key
        for (int i = 0; i < 16; ++i) hk << std::setw(2) << (int)baseKeys.hmacKey[i];
        
        // Print provided tag
        for (int i = 0; i < (int)HMAC_TAG_LEN; ++i) {
            tp << std::setw(2) << (int)tag[i];
        }
        
        // Print first 32 bytes of HMAC input for debugging
        for (int i = 0; i < 32 && i < (int)inputLen; ++i) {
            hi << std::setw(2) << (int)packetData[i];
        }
        
        log_debug("HMAC Key[0..15]: " + hk.str());
        log_debug("HMAC Input[0..31]: " + hi.str());
        log_debug("HMAC Input Length: " + std::to_string(inputLen));
        log_debug("Provided Tag: " + tp.str());
    }
    
    if (!hmac_sha256_trunc(baseKeys.hmacKey, 32, packetData, inputLen, tagCheck, HMAC_TAG_LEN)) {
        log_error("HMAC computation failed");
        return "";
    }

    // Print computed tag after computation
    {
        std::ostringstream tc;
        tc << std::hex << std::uppercase << std::setfill('0');
        for (int i = 0; i < (int)HMAC_TAG_LEN; ++i) {
            tc << std::setw(2) << (int)tagCheck[i];
        }
        log_debug("Computed Tag: " + tc.str());
    }

    // Constant-time tag comparison
    uint8_t diff = 0;
    for (size_t i = 0; i < HMAC_TAG_LEN; ++i) {
        diff |= (uint8_t)(tag[i] ^ tagCheck[i]);
    }
    
    if (diff != 0) {
        adaptive_monitor_update_hmac_failure(&gAdaptiveMonitor);
        log_error("HMAC verification failed - tags don't match");
        
        // Detailed mismatch analysis
        log_error("Tag mismatch analysis:");
        for (size_t i = 0; i < HMAC_TAG_LEN; ++i) {
            if (tag[i] != tagCheck[i]) {
                log_error("  Byte " + std::to_string(i) + ": expected 0x" + 
                         bytesToHex(&tag[i], 1) + " got 0x" + bytesToHex(&tagCheck[i], 1));
            }
        }
        return "";
    }

    log_debug("HMAC verification successful");
    
    // DON'T mark nonce as used yet - wait until after successful decryption AND validation

    // Start decryption with intermediates capture
    std::vector<uint8_t> buf = ct;

    // Debug ciphertext
    log_debug("Ciphertext: " + bytesToHex(buf.data(), std::min((size_t)32, buf.size())));

    // Step 1: Inverse Transposition (reverse of ESP32's Forward)
    uint8_t trKey8[8];
    memcpy(trKey8, messageKeys.transpositionKey, 8);
    applyTransposition(buf.data(), grid, trKey8, PermuteMode::Inverse);
    intermediates.afterTransposition = bytesToHex(buf);
    log_debug("1_After_Transposition: " + intermediates.afterTransposition.substr(0, 64));

    // Step 2: Tinkerbell XOR (same operation for encryption/decryption)
    // DEBUG: Log input before Tinkerbell XOR
    std::vector<uint8_t> bufBeforeTink = buf;
    std::ostringstream beforeTinkDebug;
    beforeTinkDebug << "[TINKERBELL] Input (first 16 bytes): " << bytesToHex(bufBeforeTink.data(), 16)
                    << " Nonce: 0x" << std::hex << std::uppercase << std::setfill('0') << std::setw(8) << nonce
                    << " Buffer size: " << buf.size() << " bytes";
    log_debug(beforeTinkDebug.str());
    
    xor_with_stream_hmac(messageKeys.tinkerbellKey, nonce, buf.data(), buf.size());
    
    intermediates.afterTinkerbell = bytesToHex(buf);
    log_debug("2_After_Tinkerbell: " + intermediates.afterTinkerbell.substr(0, 64));
    
    // DEBUG: Calculate and log the keystream that was applied
    std::ostringstream tinkKeystreamDebug;
    tinkKeystreamDebug << "[TINKERBELL] Applied keystream (first 16 bytes): ";
    for (size_t i = 0; i < 16 && i < buf.size(); ++i) {
        uint8_t ks = bufBeforeTink[i] ^ buf[i];
        tinkKeystreamDebug << std::hex << std::uppercase << std::setfill('0') << std::setw(2) << (int)ks;
    }
    log_debug(tinkKeystreamDebug.str());
    
    // Step 3: LFSR (same operation for encryption/decryption)
    // CRITICAL FIX: The LFSR must be initialized with the SAME parameters and consume keystream in the SAME order
    // as during encryption. The LFSR uses the tinkerbellKey as the chaos key, which is correct.
    // However, we need to ensure the LFSR state is initialized identically.
    // The seed is already correct (messageKeys.lfsrSeed), and the chaos key is correct (messageKeys.tinkerbellKey).
    
    // DEBUG: Log LFSR initialization parameters
    uint32_t lfsrSeed = (uint32_t)messageKeys.lfsrSeed;
    uint32_t seedBe = ((lfsrSeed >> 24) & 0xFF) | ((lfsrSeed >> 8) & 0xFF00) | 
                      ((lfsrSeed << 8) & 0xFF0000) | ((lfsrSeed << 24) & 0xFF000000);
    std::ostringstream lfsrInitDebug;
    lfsrInitDebug << "[LFSR] Initializing - Seed: 0x" << std::hex << std::uppercase << std::setfill('0') 
                  << std::setw(8) << lfsrSeed
                  << " SeedBe: 0x" << std::setw(8) << seedBe
                  << " ChaosKey[0..3]: " << bytesToHex(messageKeys.tinkerbellKey, 4)
                  << " InitialTap: 0x0029"
                  << " State: 0x" << std::setw(8) << (lfsrSeed ? lfsrSeed : 0xACE1u);
    log_debug(lfsrInitDebug.str());
    
    ChaoticLFSR32 lfsr(lfsrSeed, messageKeys.tinkerbellKey, 0x0029u);
    
    // DEBUG: Log first few bytes before XOR to compare with keystream
    std::vector<uint8_t> bufBeforeLFSR = buf;
    std::ostringstream beforeLFSRDebug;
    beforeLFSRDebug << "[LFSR] Input (first 16 bytes): " << bytesToHex(bufBeforeLFSR.data(), 16)
                    << " Buffer size: " << buf.size() << " bytes";
    log_debug(beforeLFSRDebug.str());
    
    lfsr.xorBuffer(buf.data(), buf.size());
    
    // DEBUG: Log first few bytes after XOR to verify keystream generation
    intermediates.afterLFSR = bytesToHex(buf);
    log_debug("3_After_LFSR: " + intermediates.afterLFSR.substr(0, 64));
    
    // Calculate and log the keystream that was applied (XOR of before and after)
    std::ostringstream lfsrKeystreamDebug;
    lfsrKeystreamDebug << "[LFSR] Keystream (first 16 bytes): ";
    for (size_t i = 0; i < 16 && i < buf.size(); ++i) {
        uint8_t ks = bufBeforeLFSR[i] ^ buf[i];
        lfsrKeystreamDebug << std::hex << std::uppercase << std::setfill('0') << std::setw(2) << (int)ks;
    }
    log_debug(lfsrKeystreamDebug.str());

    // Step 4: Remove salt and padding
    std::vector<uint8_t> unsalted = removeSalt(buf, grid.rows * grid.cols, saltMeta);
    intermediates.afterDepad = bytesToHex(unsalted);
    log_debug("4_After_Depad: " + intermediates.afterDepad.substr(0, 64));
    
    if (unsalted.size() < payloadLen) {
        log_error("Unsalted data too short: " + std::to_string(unsalted.size()) + " < " + std::to_string(payloadLen));
        return "";
    }

    std::string plaintext(unsalted.begin(), unsalted.begin() + payloadLen);
    
    // UTF-8 validation and cleaning
    if (!isValidUTF8(plaintext)) {
        log_warn("Decrypted text contains invalid UTF-8 sequences, cleaning...");
        plaintext = cleanUTF8(plaintext);
        
        if (plaintext.empty()) {
            log_error("Decrypted text is empty after UTF-8 cleaning");
            return "";
        }
    }
    
    // Additional validation for health data format
    if (plaintext.length() > 100) {
        log_warn("Decrypted text unusually long: " + std::to_string(plaintext.length()) + " characters");
        plaintext = plaintext.substr(0, 100);
    }
    
    // CRITICAL: Validate plaintext matches expected health data pattern before marking nonce as used
    // This allows ESP32 to retry if decryption produces garbage
    std::regex healthRegex(R"(HR-(\d+)\s+SPO2-(\d+)\s+STEPS-(\d+))");
    std::smatch matches;
    if (!std::regex_search(plaintext, matches, healthRegex)) {
        log_error("Decrypted plaintext does not match health data pattern: " + plaintext);
        log_error("HMAC passed but decryption failed - likely key mismatch or corruption");
        log_error("Debug: nonce=0x" + nonceStr.str() + 
                 " lfsrSeed=0x" + seedStr.str() +
                 " tinkerbellKey[0..3]=" + bytesToHex(messageKeys.tinkerbellKey, 4) +
                 " transpositionKey[0..3]=" + bytesToHex(messageKeys.transpositionKey, 4));
        log_error("Debug: After LFSR: " + intermediates.afterLFSR.substr(0, 64));
        log_error("Debug: After Depad: " + intermediates.afterDepad.substr(0, 64));
        // Don't mark nonce as used - allow retry
        return "";
    }
    
    // Only mark nonce as used after successful decryption AND validation
    // This ensures ESP32 can retry with the same nonce if decryption produces garbage
    if (hasNonce) {
        nonce_tracker_mark_used(&gNonceTracker, nonce);
    }
    
    log_info("Successfully decrypted: " + plaintext);

    return plaintext;
}

// WebSocket event handler
void registerEventWS(crow::SimpleApp& app) {
    static std::unordered_map<crow::websocket::connection*, uint64_t> lastHelloTime;
    static std::mutex helloMtx;

    CROW_WEBSOCKET_ROUTE(app, "/api/ws")
        .onopen([&](crow::websocket::connection& conn) {
            std::string sessionId = std::to_string(GET_TIME_MS()) + "-" + std::to_string(rand());
            
            {
                std::lock_guard<std::mutex> lock(helloMtx);
                lastHelloTime[&conn] = GET_TIME_MS();
            }
            
            log_info("WebSocket client connected: " + sessionId);
            EventBus::addClient(&conn, sessionId);
            
            nlohmann::json welcome_msg = {
                {"type", "connection_established"},
                {"message", "Connected to XenoCipher Server"},
                {"serverTime", GET_TIME_MS()},
                {"totalClients", EventBus::getClientCount()},
                {"sessionId", sessionId}
            };
            conn.send_text(welcome_msg.dump());
        })
        .onclose([&](crow::websocket::connection& conn, const std::string& reason, uint16_t code) {
            {
                std::lock_guard<std::mutex> lock(helloMtx);
                lastHelloTime.erase(&conn);
            }
            
            std::string sessionId = EventBus::getClientSession(&conn);
            log_info("WebSocket client disconnected (" + std::to_string(code) + "): " + sessionId);
            EventBus::removeClient(&conn);
        })
        .onmessage([&](crow::websocket::connection& conn, const std::string& data, bool is_binary) {
            if (is_binary) {
                return;
            }

            try {
                nlohmann::json msg = nlohmann::json::parse(data);

                if (msg.contains("type")) {
                    std::string msg_type = msg["type"];
                    
                    if (msg_type == "hello_from_frontend") {
                        uint64_t currentTime = GET_TIME_MS();
                        uint64_t lastTime = 0;
                        
                        {
                            std::lock_guard<std::mutex> lock(helloMtx);
                            auto it = lastHelloTime.find(&conn);
                            if (it != lastHelloTime.end()) {
                                lastTime = it->second;
                                it->second = currentTime;
                            }
                        }
                        
                        if (currentTime - lastTime > 5000) {
                            std::string clientId = msg.value("client", "unknown");
                            std::string sessionId = EventBus::getClientSession(&conn);
                            
                            log_info("Frontend hello from: " + clientId + " (session: " + sessionId + ")");
                            
                            nlohmann::json status_msg = {
                                {"type", "security_update"},
                                {"currentMode", "normal"},
                                {"esp32_connected", true},
                                {"serverTime", currentTime},
                                {"message", "Welcome to XenoCipher Server"}
                            };
                            EventBus::sendToClient(&conn, status_msg.dump());
                        }
                        return;
                    }
                    else if (msg_type == "hello_from_esp32") {
                        std::string deviceId = msg.value("deviceId", "unknown");
                        log_info("ESP32 connected: " + deviceId);
                        
                        nlohmann::json response = {
                            {"type", "esp32_connected"},
                            {"message", "ESP32 connection acknowledged"},
                            {"serverTime", GET_TIME_MS()},
                            {"status", "ready"}
                        };
                        EventBus::sendToClient(&conn, response);
                        return;
                    }
                }
                                // ZTM Message Handler dispatch
                if (msg.contains("type")) {
                    std::string ztm_type = msg["type"];
                    auto broadcastFn = [](const nlohmann::json& m) { EventBus::broadcast(m); };
                    if (dispatchZTMMessage(ztm_type, msg, conn, broadcastFn)) {
                        log_info("ZTM handled: " + ztm_type);
                        return;
                    }
                }

                EventBus::broadcast(msg);

                // Note: ZTM handlers are integrated via ztm_handlers.h
                // Messages like ztm_activate_request, get_ztm_status, etc. 
                // should be dispatched here if needed

            } catch (const std::exception& e) {
                log_error("WebSocket JSON parse error: " + std::string(e.what()));
            }
        });
}

// Broadcast security updates with rate limiting
void broadcastSecurityUpdate() {
    uint64_t currentTime = GET_TIME_MS();
    if (currentTime - gAdaptiveMonitor.lastSecurityBroadcast > 30000) {
        gAdaptiveMonitor.lastSecurityBroadcast = currentTime;
        
        const SecurityMetrics* metrics = adaptive_monitor_get_metrics(&gAdaptiveMonitor);
        nlohmann::json security_update = {
            {"type", "security_update"},
            {"currentMode", "normal"},
            {"decrypt_failures", metrics->decrypt_failures},
            {"hmac_failures", metrics->hmac_failures},
            {"replay_attempts", metrics->replay_attempts},
            {"requests_per_minute", metrics->requests_per_minute},
            {"esp32_connected", true},
            {"serverTime", currentTime}
        };
        EventBus::broadcast(security_update);
        log_debug("Broadcasted security update");
    }
}

// Metrics thread
static std::thread gMetricsThread;
static std::atomic<bool> gMetricsThreadRunning(true);

void metricsThreadFunction() {
    while (gMetricsThreadRunning) {
        std::this_thread::sleep_for(std::chrono::minutes(1));
        adaptive_monitor_reset_window(&gAdaptiveMonitor);
        nonce_tracker_cleanup(&gNonceTracker);
        
        const SecurityMetrics* metrics = adaptive_monitor_get_metrics(&gAdaptiveMonitor);
        log_info("Metrics - Decrypt failures: " + std::to_string(metrics->decrypt_failures) +
                ", HMAC failures: " + std::to_string(metrics->hmac_failures) +
                ", Replay attempts: " + std::to_string(metrics->replay_attempts) +
                ", Requests: " + std::to_string(metrics->requests_per_minute));
    }
}

int main() {
    // Database connection
    log_info("Initializing database connection...");
    std::unique_ptr<pqxx::connection> connPtr;
    
    const char* pgConnEnv = std::getenv("PG_CONN");
    std::string connStrEnv = pgConnEnv ? std::string(pgConnEnv) : std::string();
    
    std::vector<std::string> candidateConnStrs;
    if (!connStrEnv.empty()) candidateConnStrs.push_back(connStrEnv);
    candidateConnStrs.push_back("dbname=XenoCipherTesting user=postgres password=challa host=localhost port=5433");
    candidateConnStrs.push_back("dbname=XenoCipherTesting user=postgres password=challa host=localhost port=5432");

    for (const auto& connStr : candidateConnStrs) {
        try {
            log_info("Attempting DB connect: " + connStr);
            connPtr = std::make_unique<pqxx::connection>(connStr);
            if (connPtr->is_open()) {
                log_info("Database connection established");
                break;
            } else {
                log_error("Failed to connect to PostgreSQL (connection not open)");
                connPtr.reset();
            }
        } catch (const std::exception& e) {
            log_error("PostgreSQL connection error: " + std::string(e.what()));
            connPtr.reset();
        }
    }
    
    if (!connPtr) {
        log_error("Unable to establish PostgreSQL connection after trying all options");
        return 1;
    }

    pqxx::connection& db = *connPtr;

    // Initialize NTRU
    NTRUServer ntru;

    // Create Crow app
    crow::SimpleApp app;

    // Register WebSocket route
    registerEventWS(app);

    // CORS middleware for all routes
    auto handleCORS = [](const crow::request& req, crow::response& res) {
        res.add_header("Access-Control-Allow-Origin", "*");
        res.add_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        res.add_header("Access-Control-Allow-Headers", "Content-Type");
    };

    // GET /public-key
    CROW_ROUTE(app, "/public-key")
    .methods("GET"_method)
    ([&ntru, handleCORS]() {
        try {
            auto pubKey = ntru.getPublicKey();
            std::string pubHex = bytesToHex(pubKey);
            
            log_info("Public key requested: " + pubHex.substr(0, 32) + "...");
            
            crow::json::wvalue response;
            response["publicKey"] = "PUBHEX:" + pubHex;
            
            crow::response res(200, response);
            handleCORS(crow::request(), res);
            return res;
        } catch (const std::exception& e) {
            log_error("Error in /public-key: " + std::string(e.what()));
            crow::response res(500, crow::json::wvalue{{"error", "Server error"}});
            handleCORS(crow::request(), res);
            return res;
        }
    });

    // POST /master-key - FIXED VERSION
    CROW_ROUTE(app, "/master-key")
    .methods("POST"_method, "OPTIONS"_method)
    ([&ntru, &db, handleCORS](const crow::request& req) {
        if (req.method == "OPTIONS"_method) {
            crow::response res(200);
            handleCORS(req, res);
            return res;
        }

        try {
            log_info("Received POST /master-key request");
            
            auto body = crow::json::load(req.body);
            if (!body || !body.has("encKey")) {
                log_error("Missing encKey field in /master-key request");
                crow::response res(400, crow::json::wvalue{{"error", "Missing encKey field"}});
                handleCORS(req, res);
                return res;
            }

            std::string encKey = body["encKey"].s();
            
            if (encKey.substr(0, 7) != "ENCKEY:") {
                log_error("Invalid master key format: " + encKey.substr(0, 20) + "...");
                crow::response res(400, crow::json::wvalue{{"error", "Invalid ENCKEY format"}});
                handleCORS(req, res);
                return res;
            }
            
            std::string encKeyHex = encKey.substr(7);
            if (encKeyHex.size() % 2 != 0) {
                log_error("ENCKEY hex has odd length");
                crow::response res(400, crow::json::wvalue{{"error", "Invalid ENCKEY hex"}});
                handleCORS(req, res);
                return res;
            }

            auto encKeyBytes = hexToBytes(encKeyHex);
            if (encKeyBytes.size() != (size_t)NTRU_N * 2) {
                log_error("ENCKEY size invalid: " + std::to_string(encKeyBytes.size()));
                crow::response res(400, crow::json::wvalue{{"error", "Invalid ENCKEY size"}});
                handleCORS(req, res);
                return res;
            }

            log_info("ENCKEY received: " + bytesToHex(encKeyBytes.data(), std::min(size_t(16), encKeyBytes.size())) + "...");

            // FIXED: Always use rawKey if provided (ESP32 sends original key, not reduced)
            if (body.has("rawKey")) {
                std::string rawKey = body["rawKey"].s();
                if (rawKey.rfind("RAWKEY:", 0) == 0) {
                    std::string rawHex = rawKey.substr(7);
                    auto rawBytes = hexToBytes(rawHex);
                    if (rawBytes.size() == 32) {
                        gMasterKey = rawBytes;
                        log_info("Using RAWKEY from client for HMAC derivation");
                        
                        // Reset nonce tracker on new master key exchange (new session)
                        nonce_tracker_init(&gNonceTracker);
                        log_info("Nonce tracker reset - new session started");
                        
                        // Verify this is the same key the client will use
                        DerivedKeys testKeys;
                        if (deriveKeys(gMasterKey.data(), gMasterKey.size(), testKeys)) {
                            log_info("HMAC key derived successfully: " + bytesToHex(testKeys.hmacKey, 16));
                        }
                        
                        // Broadcast master key received
                        nlohmann::json key_msg = {
                            {"type", "master_key_received"},
                            {"message", "Master key successfully received from ESP32"},
                            {"serverTime", GET_TIME_MS()},
                            {"keySize", 32}
                        };
                        EventBus::broadcast(key_msg);
                    } else {
                        log_error("RAWKEY size invalid: " + std::to_string(rawBytes.size()));
                        crow::response res(400, crow::json::wvalue{{"error", "Invalid RAWKEY size"}});
                        handleCORS(req, res);
                        return res;
                    }
                }
            } else {
                // Fallback: decrypt with NTRU (for reduced key)
                log_info("No RAWKEY provided, decrypting with NTRU...");
                auto decryptedKey = ntru.decrypt(encKeyBytes);
                
                // The decrypted key is reduced (mod 3), we need to expand it back
                if (decryptedKey.size() == 32) {
                    gMasterKey.resize(32);
                    // Convert from reduced polynomial coefficients back to bytes
                    for (int i = 0; i < 32; ++i) {
                        // Scale reduced values (-1,0,1) to reasonable byte range
                        int8_t val = (int8_t)decryptedKey[i];
                        gMasterKey[i] = (uint8_t)((val + 1) * 85); // Map -1,0,1 to 0,85,170
                    }
                    log_info("Decrypted and expanded NTRU key");
                    
                    // Reset nonce tracker on new master key exchange (new session)
                    nonce_tracker_init(&gNonceTracker);
                    log_info("Nonce tracker reset - new session started (NTRU fallback)");
                } else {
                    log_error("Decrypted key size invalid: " + std::to_string(decryptedKey.size()));
                crow::response res(500, crow::json::wvalue{{"error", "Key decrypt error"}});
                    handleCORS(req, res);
                return res;
            }
            }

            if (gMasterKey.size() != 32) {
                log_error("Master key size invalid: " + std::to_string(gMasterKey.size()));
                crow::response res(500, crow::json::wvalue{{"error", "Key decrypt error"}});
                handleCORS(req, res);
                return res;
            }

            log_info("Master key ready: " + bytesToHex(gMasterKey.data(), 32));

            // Store in database
            try {
            pqxx::work txn(db);
                txn.exec_prepared("insert_master_key", bytesToHex(gMasterKey), std::string("received"));
            txn.commit();
                log_info("Master key stored in database");
            } catch (const std::exception& e) {
                log_error("Database error storing master key: " + std::string(e.what()));
            }
            
            crow::json::wvalue response;
            response["status"] = "OK:Encrypted key received";
            
            crow::response res(200, response);
            handleCORS(req, res);
            return res;
            
        } catch (const std::exception& e) {
            log_error("Error in /master-key: " + std::string(e.what()));
            crow::response res(500, crow::json::wvalue{{"error", "Server error"}});
            handleCORS(req, res);
            return res;
        }
    });

    // POST /health-data - FIXED COMPATIBLE ENDPOINT
    CROW_ROUTE(app, "/health-data")
    .methods("POST"_method, "OPTIONS"_method)
    ([&db, handleCORS](const crow::request& req) {
        if (req.method == "OPTIONS"_method) {
            crow::response res(200);
            handleCORS(req, res);
            return res;
        }

        if (gMasterKey.empty()) {
            log_error("No master key available for decryption");
            crow::response res(400, crow::json::wvalue{{"error", "No master key"}});
            handleCORS(req, res);
            return res;
        }
        
        try {
            // Parse request body
            nlohmann::json body;
            try {
                body = nlohmann::json::parse(req.body);
            } catch (const std::exception& e) {
                log_error("Failed to parse JSON body: " + std::string(e.what()));
                crow::response res(400, crow::json::wvalue{{"error", "Invalid JSON format"}});
                handleCORS(req, res);
                return res;
            }

            if (!body.contains("encData")) {
                log_error("Missing encData in request");
                crow::response res(400, crow::json::wvalue{{"error", "Missing encData"}});
                handleCORS(req, res);
                return res;
            }

            std::string encData = body["encData"];
            if (encData.substr(0, 9) != "ENC_DATA:") {
                log_error("Invalid ENC_DATA prefix");
                crow::response res(400, crow::json::wvalue{{"error", "Invalid ENC_DATA"}});
                handleCORS(req, res);
                return res;
            }
            
            std::string packetHex = encData.substr(9);
            auto packet = hexToBytes(packetHex);
            
            log_info("Health data received, packet size: " + std::to_string(packet.size()));
            log_debug("Received packet hex (first 64 chars): " + packetHex.substr(0, 64));
            if (packet.size() >= 12) {
                log_debug("Received packet bytes (first 12 bytes): " + bytesToHex(packet.data(), 12));
            }

            // Derive keys
            DerivedKeys baseKeys;
            if (!deriveKeys(gMasterKey.data(), gMasterKey.size(), baseKeys)) {
                log_error("Key derivation failed");
                crow::response res(500, crow::json::wvalue{{"error", "Key derivation failed"}});
                handleCORS(req, res);
                return res;
            }

            // Debug output for derived keys
            log_debug("BaseKeys - HMAC: " + bytesToHex(baseKeys.hmacKey, 32).substr(0, 32) + "...");
            log_debug("BaseKeys - Tinkerbell: " + bytesToHex(baseKeys.tinkerbellKey, 16));
            log_debug("BaseKeys - Transposition: " + bytesToHex(baseKeys.transpositionKey, 16));
            
            // Log master key hash for debugging key mismatches
            std::ostringstream masterKeyHash;
            masterKeyHash << std::hex << std::uppercase << std::setfill('0');
            for (size_t i = 0; i < 8 && i < gMasterKey.size(); ++i) {
                masterKeyHash << std::setw(2) << (int)gMasterKey[i];
            }
            log_debug("Master key (first 8 bytes): " + masterKeyHash.str() + "...");

            // Decrypt with intermediates capture
            PipelineIntermediates intermediates;
            auto start = std::chrono::high_resolution_clock::now();
            
            std::string plaintext = pipelineDecryptPacketWithIntermediates(
                baseKeys, packet, packet.size(), intermediates);
            
            auto end = std::chrono::high_resolution_clock::now();
            double decryptMs = std::chrono::duration<double, std::milli>(end - start).count();

            if (plaintext.empty()) {
                log_error("Decryption failed");
                crow::response res(400, crow::json::wvalue{{"error", "Decryption failed"}});
                handleCORS(req, res);
                return res;
            }

            log_info("Successfully decrypted: " + plaintext + " (time: " + std::to_string(decryptMs) + " ms)");

            // Rate-limited security update
            broadcastSecurityUpdate();

            // Forward encryption update if present
            if (body.contains("type") && body["type"] == "encryption_update") {
                nlohmann::json encryptionUpdate = body;
                encryptionUpdate["serverTime"] = GET_TIME_MS();
                EventBus::broadcast(encryptionUpdate);
                log_debug("Forwarded encryption update to frontend");
            }

            // Parse health data (already validated in pipelineDecryptPacketWithIntermediates)
            // Plaintext is guaranteed to match pattern at this point
            std::regex healthRegex(R"(HR-(\d+)\s+SPO2-(\d+)\s+STEPS-(\d+))");
            std::smatch matches;
            
            nlohmann::json healthData;
            // Plaintext is guaranteed to match pattern (validation happens in decryption function)
            if (std::regex_search(plaintext, matches, healthRegex)) {
                int hr = std::stoi(matches[1]);
                int spo2 = std::stoi(matches[2]);
                int steps = std::stoi(matches[3]);

                healthData = {
                    {"heartRate", hr},
                    {"spo2", spo2},
                    {"steps", steps}
                };

                // Send health data update
                nlohmann::json healthMsg = {
                    {"type", "health_data_update"},
                    {"heartRate", hr},
                    {"spo2", spo2},
                    {"steps", steps},
                    {"time", GET_TIME_MS()}
                };
                EventBus::broadcast(healthMsg);

                // Send session summary
                nlohmann::json summaryMsg = {
                    {"type", "session_summary_update"},
                    {"sessionSummary", {
                        {"adaptiveMode", "normal"},
                        {"dataStored", true},
                        {"decryptionTime", decryptMs},
                        {"encryptionTime", body.value("encryptionTime", 0.0)},
                        {"totalTime", decryptMs + body.value("encryptionTime", 0.0)},
                        {"handshakeSuccess", true},
                        {"finalPlaintext", safeJsonString(plaintext)}
                    }}
                };
                EventBus::broadcast(summaryMsg);

                // Store in database
                try {
            pqxx::work txn(db);
                    txn.exec_prepared("insert_health_data", hr, spo2, steps);
            txn.commit();
                    log_info("Health data stored in database: HR=" + std::to_string(hr) + 
                             " SPO2=" + std::to_string(spo2) + " STEPS=" + std::to_string(steps));
                } catch (const std::exception& e) {
                    log_error("Database error storing health data: " + std::string(e.what()));
                }
            } else {
                log_info("Plaintext doesn't match health data pattern: " + plaintext);
            }

            // Send comprehensive decryption update with ALL intermediates
            nlohmann::json decryptMsg = {
                {"type", "decryption_update"},
                {"encryptedPacket", packetHex},
                {"finalPlaintext", safeJsonString(plaintext)},
                {"decryptionTime", decryptMs},
                {"serverTime", GET_TIME_MS()},
                {"pipeline", {
                    {"afterTransposition", safeJsonString(intermediates.afterTransposition)},
                    {"afterTinkerbell", safeJsonString(intermediates.afterTinkerbell)},
                    {"afterLFSR", safeJsonString(intermediates.afterLFSR)},
                    {"afterDepad", safeJsonString(intermediates.afterDepad)}
                }}
            };

            // Add health data if available
            if (!healthData.empty()) {
                decryptMsg["healthData"] = healthData;
            }

            // Broadcast the decryption update
            EventBus::broadcast(decryptMsg);
            log_info("Sent decryption update to frontend with full pipeline data");

            crow::response res(200, crow::json::wvalue{{"status", "OK:DECRYPTED"}});
            handleCORS(req, res);
            return res;
            
        } catch (const std::exception& e) {
            log_error("Error in /health-data: " + std::string(e.what()));
            crow::response res(500, crow::json::wvalue{{"error", "Server error: " + std::string(e.what())}});
            handleCORS(req, res);
            return res;
        }
    });

    // POST /adaptive-switch - Adaptive mode/recipe switching
    CROW_ROUTE(app, "/adaptive-switch")
    .methods("POST"_method, "OPTIONS"_method)
    ([handleCORS](const crow::request& req) {
        if (req.method == "OPTIONS"_method) {
            crow::response res(200);
            handleCORS(req, res);
            return res;
        }
        
        try {
            nlohmann::json body = nlohmann::json::parse(req.body);
            
            if (!body.contains("mode") || !body.contains("recipe")) {
                log_error("Missing mode or recipe in adaptive-switch request");
                crow::response res(400, crow::json::wvalue{{"error", "Missing mode or recipe"}});
                handleCORS(req, res);
                return res;
            }
            
            std::string mode = body["mode"];  // "normal" or "ztm"
            std::string recipe = body["recipe"];  // "full_stack", "chacha_heavy", etc.
            
            log_info("Adaptive switch requested: mode=" + mode + ", recipe=" + recipe);
            
            // Broadcast mode change request to ESP32 via WebSocket
            nlohmann::json switchMsg = {
                {"type", "adaptive_switch_request"},
                {"mode", mode},
                {"recipe", recipe},
                {"serverTime", GET_TIME_MS()},
                {"requiresAck", true}
            };
            EventBus::broadcast(switchMsg);
            
            // Emit telemetry event
            nlohmann::json telemetry = {
                {"type", "telemetry"},
                {"event", "mode_change_requested"},
                {"data", "mode=" + mode + ",recipe=" + recipe},
                {"serverTime", GET_TIME_MS()}
            };
            EventBus::broadcast(telemetry);
            
            crow::response res(200, crow::json::wvalue{
                {"status", "OK"},
                {"message", "Mode switch request sent to ESP32"},
                {"mode", mode},
                {"recipe", recipe}
            });
            handleCORS(req, res);
            return res;
            
        } catch (const std::exception& e) {
            log_error("Error in /adaptive-switch: " + std::string(e.what()));
            crow::response res(500, crow::json::wvalue{{"error", "Server error: " + std::string(e.what())}});
            handleCORS(req, res);
            return res;
        }
    });
    
    // POST /adaptive-ack - ESP32 acknowledges mode change
    CROW_ROUTE(app, "/adaptive-ack")
    .methods("POST"_method, "OPTIONS"_method)
    ([handleCORS](const crow::request& req) {
        if (req.method == "OPTIONS"_method) {
            crow::response res(200);
            handleCORS(req, res);
            return res;
        }
        
        try {
            nlohmann::json body = nlohmann::json::parse(req.body);
            
            std::string mode = body.value("mode", "normal");
            std::string recipe = body.value("recipe", "full_stack");
            bool success = body.value("success", true);
            
            log_info("ESP32 acknowledged mode change: mode=" + mode + ", recipe=" + recipe + ", success=" + (success ? "true" : "false"));
            
            // Broadcast acknowledgment
            nlohmann::json ackMsg = {
                {"type", "adaptive_switch_acknowledged"},
                {"mode", mode},
                {"recipe", recipe},
                {"success", success},
                {"serverTime", GET_TIME_MS()}
            };
            EventBus::broadcast(ackMsg);
            
            crow::response res(200, crow::json::wvalue{{"status", "OK"}});
            handleCORS(req, res);
            return res;
            
        } catch (const std::exception& e) {
            log_error("Error in /adaptive-ack: " + std::string(e.what()));
            crow::response res(500, crow::json::wvalue{{"error", "Server error"}});
            handleCORS(req, res);
            return res;
        }
    });
    
    // GET /metrics
    CROW_ROUTE(app, "/metrics")
    .methods("GET"_method)
    ([handleCORS]() {
        const SecurityMetrics* metrics = adaptive_monitor_get_metrics(&gAdaptiveMonitor);

        nlohmann::json response = {
            {"decryptFailures", metrics->decrypt_failures},
            {"hmacFailures", metrics->hmac_failures},
            {"replayAttempts", metrics->replay_attempts},
            {"requests", metrics->requests_per_minute}
        };

        crow::response res(200, response.dump());
        res.add_header("Content-Type", "application/json");
        handleCORS(crow::request(), res);
        return res;
    });

    // GET /clients - WebSocket client information
    CROW_ROUTE(app, "/clients")
    .methods("GET"_method)
    ([handleCORS]() {
        nlohmann::json response = {
            {"totalClients", EventBus::getClientCount()},
            {"serverTime", GET_TIME_MS()}
        };

        crow::response res(200, response.dump());
        res.add_header("Content-Type", "application/json");
        handleCORS(crow::request(), res);
        return res;
    });

    // Initialize database schema
    try {
            pqxx::work ddl(db);
        ddl.exec("CREATE TABLE IF NOT EXISTS master_keys ("
                 "id serial PRIMARY KEY,"
                 "master_key text NOT NULL,"
                 "status text NOT NULL DEFAULT 'received',"
                 "created_at timestamptz NOT NULL DEFAULT now()"
                     ")");

        ddl.exec("CREATE TABLE IF NOT EXISTS health_data ("
                 "id serial PRIMARY KEY,"
                 "heart_rate smallint,"
                 "spo2 smallint,"
                 "steps integer,"
                 "created_at timestamptz NOT NULL DEFAULT now()"
                 ")");
            ddl.commit();

        // Prepare statements
        pqxx::work prep(db);
        prep.exec("PREPARE insert_master_key (text, text) AS "
                  "INSERT INTO master_keys (master_key, status) VALUES ($1, $2)");
        prep.exec("PREPARE insert_health_data (smallint, smallint, integer) AS "
                  "INSERT INTO health_data (heart_rate, spo2, steps) VALUES ($1, $2, $3)");
        prep.commit();

        log_info("Database schema initialized");
    } catch (const std::exception& e) {
        log_error("Database initialization error: " + std::string(e.what()));
        return 1;
    }

    // Initialize security subsystems
    adaptive_monitor_init(&gAdaptiveMonitor);
    nonce_tracker_init(&gNonceTracker);
    log_info("Nonce tracker reset for new session");

    // Start metrics thread
    gMetricsThread = std::thread(metricsThreadFunction);

    // Start server
    log_info("Starting XenoCipher Server on 0.0.0.0:8081...");
    log_info("Available endpoints:");
    log_info("  GET  /public-key");
    log_info("  POST /master-key"); 
    log_info("  POST /health-data");
    log_info("  GET  /metrics");
    log_info("  GET  /clients");
    log_info("  WS   /api/ws");
    log_info("Press Ctrl+C to stop");

    try {
        app.bindaddr("0.0.0.0").port(8081).multithreaded().run();
    } catch (const std::exception& e) {
        log_error("Server error: " + std::string(e.what()));
    }

    // Cleanup
    gMetricsThreadRunning = false;
    if (gMetricsThread.joinable()) {
        gMetricsThread.join();
    }

    return 0;
}