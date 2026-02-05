// server/api/ztm_handlers.h
// Zero Trust Mode — Secure Two-Phase Commit for Recipe Switching
#pragma once

#include <crow.h>
#include <nlohmann/json.hpp>
#include <string>
#include <mutex>
#include <thread>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <vector>
#include <utility>
#include <functional>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <map>
#include <random>
#include <algorithm>
#include "../../lib/Heuristics_Manager/include/heuristics_manager.h"
#include "../../lib/HMAC/include/hmac.h"

class EventBus;
extern std::vector<uint8_t> gMasterKey;
extern uint32_t g_lastSeenNonce;

// --- Two-Phase Commit constants (exact per spec) ---
static const int ACK_TIMEOUT_MS = 3000;
static const int COMMIT_TIMEOUT_MS = 5000;
static const int MAX_RETRIES = 3;

// --- Canonical JSON (keys sorted lexicographically for HMAC) ---
inline std::string canonicalize_json(const nlohmann::json& j) {
    if (j.is_object()) {
        std::vector<std::string> keys;
        for (auto it = j.begin(); it != j.end(); ++it) {
            if (it.key() != "hmac")
                keys.push_back(it.key());
        }
        std::sort(keys.begin(), keys.end());
        std::ostringstream os;
        os << "{";
        for (size_t i = 0; i < keys.size(); ++i) {
            if (i) os << ",";
            os << "\"" << keys[i] << "\":" << canonicalize_json(j[keys[i]]);
        }
        os << "}";
        return os.str();
    }
    if (j.is_array()) {
        std::ostringstream os;
        os << "[";
        for (size_t i = 0; i < j.size(); ++i) {
            if (i) os << ",";
            os << canonicalize_json(j[i]);
        }
        os << "]";
        return os.str();
    }
    if (j.is_string()) {
        std::string s = j.get<std::string>();
        std::string out = "\"";
        for (char c : s) {
            if (c == '\\') out += "\\\\";
            else if (c == '"') out += "\\\"";
            else out += c;
        }
        out += "\"";
        return out;
    }
    if (j.is_boolean()) return j.get<bool>() ? "true" : "false";
    if (j.is_number_integer()) return std::to_string(j.get<int64_t>());
    if (j.is_number_unsigned()) return std::to_string(j.get<uint64_t>());
    if (j.is_number_float()) return std::to_string(j.get<double>());
    if (j.is_null()) return "null";
    return "null";
}

inline std::string computeControlHmacHex(const std::string& canonicalStr) {
    if (gMasterKey.empty() || gMasterKey.size() < 32) return "";
    uint8_t tag[32];
    if (!hmac_sha256_full(gMasterKey.data(), 32,
                          reinterpret_cast<const uint8_t*>(canonicalStr.data()), canonicalStr.size(),
                          tag)) return "";
    std::ostringstream os;
    os << std::hex << std::setfill('0');
    for (int i = 0; i < 32; ++i) os << std::setw(2) << (int)tag[i];
    return os.str();
}

inline bool verifyControlHmac(const nlohmann::json& msg) {
    if (!msg.contains("hmac")) return false;
    std::string expected = msg["hmac"].get<std::string>();
    nlohmann::json copy = msg;
    copy.erase("hmac");
    std::string canonical = canonicalize_json(copy);
    std::string computed = computeControlHmacHex(canonical);
    return computed.size() == expected.size() && computed == expected;
}

inline void addControlHmac(nlohmann::json& j) {
    std::string canonical = canonicalize_json(j);
    std::string hmacHex = computeControlHmacHex(canonical);
    if (!hmacHex.empty()) j["hmac"] = hmacHex;
}

// --- Proposal state for Two-Phase Commit ---
enum class ProposalStateEnum { PENDING, COMMIT_SENT };
struct ProposalState {
    std::string proposalId;
    uint32_t epoch = 0;
    std::string targetRecipe;
    ProposalStateEnum state = ProposalStateEnum::PENDING;
    uint64_t commitNonce = 0;
    bool ackReceived = false;
    uint64_t sendTime = 0;
    uint64_t commitTime = 0;
    int retries = 0;
    std::string deviceId;
    std::string lastCommitMsg; // for retry
};

// --- ZTM State Manager (proposal-based Two-Phase Commit) ---
class ZTMStateManager {
private:
    static ZTMStateManager* instance;
    static std::mutex instanceMutex;
    std::mutex stateMutex;
    bool isActive;
    uint32_t currentEpoch;
    std::string activeRecipe;
    std::string passkey;
    uint64_t activatedAt;
    std::string lastSwitchReason;
    HeuristicsManager heuristicsManager;
    std::atomic<bool> adaptiveLoopRunning;
    std::thread adaptiveThread;
    std::thread timeoutThread;
    uint64_t lastRecipeSwitchTime;
    static const uint64_t MIN_SWITCH_INTERVAL_MS = 5000;
    std::map<std::string, ProposalState> proposals;
    uint64_t commitCounter;
    uint64_t lastCommitNonce;
    std::function<void(const nlohmann::json&)> broadcastFn;

    ZTMStateManager()
        : isActive(false), currentEpoch(1), activeRecipe("CHAOS_ONLY"), passkey("1234"),
          activatedAt(0), lastSwitchReason(""), adaptiveLoopRunning(false),
          lastRecipeSwitchTime(0), commitCounter(0), lastCommitNonce(0) {
        heuristicsManager.loadThresholdsFromJSON("heuristics.json");
    }

public:
    ~ZTMStateManager() { stopAdaptiveLoop(); }

    static ZTMStateManager* getInstance() {
        std::lock_guard<std::mutex> lock(instanceMutex);
        if (!instance) instance = new ZTMStateManager();
        return instance;
    }

    std::string getPasskey() {
        const char* envPasskey = std::getenv("ZTM_PASSKEY");
        return envPasskey ? std::string(envPasskey) : passkey;
    }

    bool verifyPasskey(const std::string& inputPasskey) {
        if (inputPasskey.length() != 4) return false;
        for (char c : inputPasskey) if (!std::isdigit(c)) return false;
        return inputPasskey == getPasskey();
    }

    bool activate(const std::string& sessionKey = "", const std::string& ephemeralId = "") {
        std::lock_guard<std::mutex> lock(stateMutex);
        isActive = true;
        currentEpoch = 1;
        activeRecipe = "CHAOS_ONLY";
        activatedAt = currentTimeMs();
        lastSwitchReason = "ZTM activated - baseline recipe";
        heuristicsManager.enableZTM(true);
        return true;
    }

    void deactivate() {
        std::lock_guard<std::mutex> lock(stateMutex);
        isActive = false;
        heuristicsManager.enableZTM(false);
        lastSwitchReason = "ZTM deactivated";
    }

    static uint64_t currentTimeMs() {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }

    // ISO8601 UTC timestamp for control messages
    static std::string nowIso8601Utc() {
        auto now = std::chrono::system_clock::now();
        auto tt = std::chrono::system_clock::to_time_t(now);
        struct tm tm_buf;
#ifdef _WIN32
        gmtime_s(&tm_buf, &tt);
#else
        gmtime_r(&tt, &tm_buf);
#endif
        char buf[32];
        std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm_buf);
        return std::string(buf);
    }

    static std::string generateProposalId() {
        static std::random_device rd;
        static std::mt19937_64 gen(rd());
        static std::uniform_int_distribution<uint32_t> d(0, 0xFFFFFFFF);
        std::ostringstream os;
        os << std::hex << std::setfill('0')
           << std::setw(8) << d(gen) << "-" << std::setw(4) << (d(gen) & 0xFFFF) << "-"
           << "4" << std::setw(3) << (d(gen) % 0x1000) << "-"
           << std::setw(4) << ((d(gen) & 0x3FFF) | 0x8000) << "-"
           << std::setw(12) << (d(gen) & 0xFFFFFF) << (d(gen) & 0xFFFFFFFF);
        return os.str();
    }

    // Propose switch: send switch_propose with payload/signature structure
    // Message format: { "type": "switch_propose", "payload": {...}, "signature": "..." }
    std::string proposeSwitchToDevice(const std::string& targetRecipe, const std::string& reason,
                                      const std::function<void(const nlohmann::json&)>& broadcast) {
        static const std::vector<std::string> validRecipes = {
            "CHAOS_ONLY", "SALSA_LIGHT", "CHACHA_HEAVY", "FULL_STACK", "STREAM_FOCUS"
        };
        bool valid = false;
        for (const auto& r : validRecipes) { if (r == targetRecipe) { valid = true; break; } }
        if (!valid) {
            std::cout << "[ZTM][SEND_PROPOSE] REJECTED: invalid recipe '" << targetRecipe << "'" << std::endl;
            return "";
        }

        std::string proposalId;
        uint32_t epoch;
        std::string proposedAt;
        {
            std::lock_guard<std::mutex> lock(stateMutex);
            if (!isActive) {
                std::cout << "[ZTM][SEND_PROPOSE] REJECTED: ZTM not active" << std::endl;
                return "";
            }
            uint64_t now = currentTimeMs();
            if (now - lastRecipeSwitchTime < MIN_SWITCH_INTERVAL_MS) {
                std::cout << "[ZTM][SEND_PROPOSE] REJECTED: cooldown active" << std::endl;
                return "";
            }
            proposalId = generateProposalId();
            epoch = ++currentEpoch;
            proposedAt = nowIso8601Utc();
            ProposalState ps;
            ps.proposalId = proposalId;
            ps.epoch = epoch;
            ps.targetRecipe = targetRecipe;
            ps.state = ProposalStateEnum::PENDING;
            ps.sendTime = now;
            ps.retries = 0;
            proposals[proposalId] = ps;
        }

        // Build payload with sorted keys: epoch, proposalId, proposedAt, targetRecipe
        nlohmann::json payload = {
            {"epoch", epoch},
            {"proposalId", proposalId},
            {"proposedAt", proposedAt},
            {"targetRecipe", targetRecipe}
        };
        std::string canonicalPayload = canonicalize_json(payload);
        
        // DIAGNOSTIC: Log master key used for signature
        std::cout << "[ZTM][SEND_PROPOSE] Master key (first 16 bytes): ";
        for (size_t i = 0; i < std::min<size_t>(16, gMasterKey.size()); ++i) {
            printf("%02X", gMasterKey[i]);
        }
        std::cout << std::endl;
        
        std::string signature = computeControlHmacHex(canonicalPayload);
        
        if (signature.empty()) {
            std::cout << "[ZTM][SEND_PROPOSE] REJECTED: HMAC key not available" << std::endl;
            return "";
        }

        nlohmann::json propose = {
            {"type", "switch_propose"},
            {"payload", payload},
            {"signature", signature}
        };
        
        std::cout << "[ZTM][SEND_PROPOSE] proposalId=" << proposalId 
                  << " epoch=" << epoch 
                  << " targetRecipe=" << targetRecipe
                  << " payload=" << canonicalPayload
                  << " signature=" << signature << std::endl;
        
        broadcast(propose);
        return proposalId;
    }

    // On switch_ack: verify HMAC over payload, find proposal, send switch_commit with payload/signature
    // REQUIRED format: { "type": "switch_ack", "payload": {...}, "signature": "..." }
    bool handleSwitchAck(const nlohmann::json& ack, const std::function<void(const nlohmann::json&)>& broadcast) {
        // Strictly require new payload/signature format - no legacy fallback
        if (!ack.contains("payload") || !ack.contains("signature")) {
            std::cout << "[ZTM][RECV_ACK] REJECTED: Missing payload/signature fields. Device must use new format." << std::endl;
            return false;
        }

        // New payload/signature format
        nlohmann::json payload = ack["payload"];
        std::string signature = ack["signature"].get<std::string>();
        std::string canonicalPayload = canonicalize_json(payload);
        std::string computed = computeControlHmacHex(canonicalPayload);
        
        if (computed.empty() || computed != signature) {
            std::cout << "[ZTM][RECV_ACK] REJECTED: HMAC mismatch" << std::endl;
            std::cout << "[ZTM][RECV_ACK]   expected=" << signature << std::endl;
            std::cout << "[ZTM][RECV_ACK]   computed=" << computed << std::endl;
            std::cout << "[ZTM][RECV_ACK]   canonical=" << canonicalPayload << std::endl;
            return false;
        }

        std::string proposalId = payload.value("proposalId", "");
        std::string deviceId = payload.value("deviceId", "");
        uint32_t lastSeenNonce = payload.value("lastSeenNonce", (uint32_t)0);
        uint64_t deviceEpoch = payload.value("epoch", (uint64_t)0);
        bool ready = payload.value("ready", false);
        
        std::cout << "[ZTM][RECV_ACK] proposalId=" << proposalId 
                  << " deviceId=" << deviceId
                  << " lastSeenNonce=" << lastSeenNonce 
                  << " epoch=" << deviceEpoch 
                  << " ready=" << (ready ? "true" : "false") << std::endl;

        if (proposalId.empty() || !ready) return false;

        std::lock_guard<std::mutex> lock(stateMutex);
        auto it = proposals.find(proposalId);
        if (it == proposals.end()) {
            std::cout << "[ZTM][RECV_ACK] REJECTED: unknown proposalId=" << proposalId << std::endl;
            return false;
        }
        ProposalState& ps = it->second;
        if (ps.ackReceived) {
            std::cout << "[ZTM][RECV_ACK] (idempotent) already received for proposalId=" << proposalId << std::endl;
            return true;
        }
        ps.ackReceived = true;
        ps.deviceId = deviceId;
        // commitNonce = lastSeenNonce + 1 (safe boundary)
        ps.commitNonce = ((uint64_t)ps.epoch << 32) | (lastSeenNonce + 1);
        lastCommitNonce = ps.commitNonce;
        ps.state = ProposalStateEnum::COMMIT_SENT;
        ps.commitTime = currentTimeMs();
        ps.retries = 0;

        // Build commit payload with sorted keys: commitNonce, committedAt, epoch, proposalId
        std::string committedAt = nowIso8601Utc();
        nlohmann::json commitPayload = {
            {"commitNonce", ps.commitNonce},
            {"committedAt", committedAt},
            {"epoch", ps.epoch},
            {"proposalId", proposalId}
        };
        std::string commitCanonical = canonicalize_json(commitPayload);
        std::string commitSig = computeControlHmacHex(commitCanonical);
        
        nlohmann::json commit = {
            {"type", "switch_commit"},
            {"payload", commitPayload},
            {"signature", commitSig}
        };
        ps.lastCommitMsg = commit.dump();
        
        std::cout << "[ZTM][SEND_COMMIT] proposalId=" << proposalId 
                  << " commitNonce=" << ps.commitNonce
                  << " epoch=" << ps.epoch << std::endl;
        
        broadcast(commit);
        return true;
    }

    // On switch_done: verify HMAC over payload, match proposalId and commitNonce, finalize activeRecipe.
    // REQUIRED format: { "type": "switch_done", "payload": {...}, "signature": "..." }
    bool handleSwitchDone(const nlohmann::json& done) {
        // Strictly require new payload/signature format - no legacy fallback
        if (!done.contains("payload") || !done.contains("signature")) {
            std::cout << "[ZTM][RECV_DONE] REJECTED: Missing payload/signature fields. Device must use new format." << std::endl;
            return false;
        }
        
        // New payload/signature format
        nlohmann::json payload = done["payload"];
        std::string signature = done["signature"].get<std::string>();
        std::string canonicalPayload = canonicalize_json(payload);
        std::string computed = computeControlHmacHex(canonicalPayload);
        
        if (computed.empty() || computed != signature) {
            std::cout << "[ZTM][RECV_DONE] REJECTED: HMAC mismatch" << std::endl;
            std::cout << "[ZTM][RECV_DONE]   expected=" << signature << std::endl;
            std::cout << "[ZTM][RECV_DONE]   computed=" << computed << std::endl;
            return false;
        }
        
        std::string proposalId = payload.value("proposalId", "");
        uint64_t commitNonce = payload.value("commitNonce", (uint64_t)0);
        std::string deviceId = payload.value("deviceId", "");
        uint64_t doneEpoch = payload.value("epoch", (uint64_t)0);
        std::string switchedAt = payload.value("switchedAt", "");
        
        std::cout << "[ZTM][RECV_DONE] proposalId=" << proposalId 
                  << " commitNonce=" << commitNonce
                  << " deviceId=" << deviceId
                  << " epoch=" << doneEpoch
                  << " switchedAt=" << switchedAt << std::endl;
        
        if (proposalId.empty()) return false;

        std::string recipe;
        uint32_t epoch = 0;
        {
            std::lock_guard<std::mutex> lock(stateMutex);
            auto it = proposals.find(proposalId);
            if (it == proposals.end()) {
                std::cout << "[ZTM][RECV_DONE] REJECTED: unknown proposalId=" << proposalId << std::endl;
                return false;
            }
            if (it->second.commitNonce != commitNonce) {
                std::cout << "[ZTM][RECV_DONE] REJECTED: commitNonce mismatch expected=" 
                          << it->second.commitNonce << " got=" << commitNonce << std::endl;
                return false;
            }
            recipe = it->second.targetRecipe;
            epoch = it->second.epoch;
            activeRecipe = recipe;
            lastSwitchReason = "Committed via switch_done";
            lastRecipeSwitchTime = currentTimeMs();
            proposals.erase(it);
        }
        std::cout << "[ZTM][RECV_DONE] SUCCESS: recipe switched to " << recipe 
                  << " epoch=" << epoch << std::endl;
        if (broadcastFn) {
            // Explicitly broadcast an authoritative active-recipe update
            nlohmann::json status = getStatus();
            status["type"] = "active_recipe_updated";
            broadcastFn(status);
        }
        return true;
    }

    // Handle switch_nack from device
    // REQUIRED format: { "type": "switch_nack", "payload": {...}, "signature": "..." }
    void handleSwitchNack(const nlohmann::json& nack) {
        std::string proposalId;
        std::string reason;
        uint64_t currentEpoch = 0;
        
        // Strictly require new payload/signature format - no legacy fallback
        if (!nack.contains("payload") || !nack.contains("signature")) {
            std::cout << "[ZTM][RECV_NACK] WARNING: Missing payload/signature fields. Device should use new format." << std::endl;
            // For NACK, still try to extract what we can to abort the proposal
            proposalId = nack.value("proposalId", "");
            reason = nack.value("reason", "unknown (legacy format)");
        } else {
            nlohmann::json payload = nack["payload"];
            std::string signature = nack["signature"].get<std::string>();
            std::string canonicalPayload = canonicalize_json(payload);
            std::string computed = computeControlHmacHex(canonicalPayload);
            
            if (computed.empty() || computed != signature) {
                std::cout << "[ZTM][RECV_NACK] WARNING: HMAC mismatch (still processing)" << std::endl;
            }
            proposalId = payload.value("proposalId", "");
            reason = payload.value("reason", "");
            currentEpoch = payload.value("currentEpoch", (uint64_t)0);
        }
        
        std::cout << "[ZTM][RECV_NACK] proposalId=" << proposalId 
                  << " reason=" << reason
                  << " deviceEpoch=" << currentEpoch << std::endl;
        
        if (!proposalId.empty()) {
            std::lock_guard<std::mutex> lock(stateMutex);
            auto it = proposals.find(proposalId);
            if (it != proposals.end()) {
                proposals.erase(it);
                std::cout << "[ZTM][RECV_NACK] Proposal " << proposalId << " aborted" << std::endl;
            }
        }
    }

    void setBroadcastFn(std::function<void(const nlohmann::json&)> fn) {
        std::lock_guard<std::mutex> lock(stateMutex);
        broadcastFn = std::move(fn);
    }

    void tickTimeoutsAndRetries(const std::function<void(const nlohmann::json&)>& broadcast) {
        uint64_t now = currentTimeMs();
        std::vector<std::string> toErase;
        std::vector<std::pair<std::string, std::string>> toResendCommit;
        {
            std::lock_guard<std::mutex> lock(stateMutex);
            for (auto& [pid, ps] : proposals) {
                if (ps.state == ProposalStateEnum::PENDING) {
                    if (now - ps.sendTime > (uint64_t)ACK_TIMEOUT_MS) {
                        ps.retries++;
                        if (ps.retries > MAX_RETRIES) {
                            toErase.push_back(pid);
                            std::cout << "[SERVER][CONTROL] Abort proposal (no ack) proposalId=" << pid << std::endl;
                        }
                    }
                } else if (ps.state == ProposalStateEnum::COMMIT_SENT) {
                    if (now - ps.commitTime > (uint64_t)COMMIT_TIMEOUT_MS) {
                        ps.retries++;
                        if (ps.retries > MAX_RETRIES) {
                            toErase.push_back(pid);
                            std::cout << "[SERVER][CONTROL] Abort proposal (no done) proposalId=" << pid << std::endl;
                        } else if (!ps.lastCommitMsg.empty()) {
                            toResendCommit.push_back({pid, ps.lastCommitMsg});
                            ps.commitTime = now;
                            std::cout << "[SERVER][CONTROL] Retry switch_commit proposalId=" << pid << std::endl;
                        }
                    }
                }
            }
            for (const auto& pid : toErase) proposals.erase(pid);
        }
        for (const auto& [pid, msg] : toResendCommit) {
            try {
                broadcast(nlohmann::json::parse(msg));
            } catch (...) {}
        }
    }

    nlohmann::json getStatus() {
        std::lock_guard<std::mutex> lock(stateMutex);
        HeuristicMetrics metrics = heuristicsManager.getLatestMetrics();
        size_t pendingCount = proposals.size();
        return {
            // Use unified message type so frontend can treat this
            // as the authoritative ZTM status (including recipe).
            {"type", "ztm_status"},
            {"active", isActive},
            {"epoch", currentEpoch},
            {"recipe", activeRecipe},
            {"pendingProposals", (int)pendingCount},
            {"activatedAt", activatedAt},
            {"lastSwitchReason", lastSwitchReason},
            {"heuristics", {
                {"entropy", metrics.entropy},
                {"latency", metrics.latency},
                {"cpuUsage", metrics.cpuUsage},
                {"hmacFailures", metrics.hmacFailures},
                {"decryptFailures", metrics.decryptFailures},
                {"replayAttempts", metrics.replayAttempts},
                {"malformedPackets", metrics.malformedPackets},
                {"timingAnomalies", metrics.timingAnomalies}
            }},
            {"threatLevel", static_cast<int>(heuristicsManager.getCurrentThreatLevel())},
            {"serverTime", currentTimeMs()},
            {"lastCommitNonce", lastCommitNonce},
            {"lastSeenNonce", g_lastSeenNonce}
        };
    }

    nlohmann::json getHeuristics() {
        std::lock_guard<std::mutex> lock(stateMutex);
        HeuristicMetrics metrics = heuristicsManager.getLatestMetrics();
        return {
            {"type", "heuristics_update"},
            {"metrics", {
                {"entropyAfter", metrics.entropy},
                {"latencyMs", metrics.latency},
                {"cpuPercent", metrics.cpuUsage},
                {"hmacFailures", metrics.hmacFailures},
                {"decryptFailures", metrics.decryptFailures},
                {"replayAttempts", metrics.replayAttempts},
                {"malformedPackets", metrics.malformedPackets},
                {"timingAnomalies", metrics.timingAnomalies}
            }},
            {"threatLevel", static_cast<int>(heuristicsManager.getCurrentThreatLevel())},
            {"currentRecipe", activeRecipe},
            {"epoch", currentEpoch},
            {"lastCommitNonce", lastCommitNonce},
            {"lastSeenNonce", g_lastSeenNonce},
            {"serverTime", currentTimeMs()}
        };
    }

    void simulateHeuristics(const nlohmann::json& values) {
        HeuristicMetrics metrics = heuristicsManager.getLatestMetrics();

        // Accept both backend-oriented names and frontend/UI names
        // so dev-panel simulations always drive the same engine.
        if (values.contains("entropy")) metrics.entropy = values["entropy"].get<double>();
        if (values.contains("entropyAfter")) metrics.entropy = values["entropyAfter"].get<double>();

        if (values.contains("latency")) metrics.latency = values["latency"].get<double>();
        if (values.contains("latencyMs")) metrics.latency = values["latencyMs"].get<double>();

        if (values.contains("cpuUsage")) metrics.cpuUsage = values["cpuUsage"].get<double>();
        if (values.contains("cpuPercent")) metrics.cpuUsage = values["cpuPercent"].get<double>();

        if (values.contains("hmacFailures")) metrics.hmacFailures = values["hmacFailures"].get<uint32_t>();
        if (values.contains("decryptFailures")) metrics.decryptFailures = values["decryptFailures"].get<uint32_t>();
        if (values.contains("replayAttempts")) metrics.replayAttempts = values["replayAttempts"].get<uint32_t>();
        if (values.contains("malformedPackets")) metrics.malformedPackets = values["malformedPackets"].get<uint32_t>();
        if (values.contains("timingAnomalies")) metrics.timingAnomalies = values["timingAnomalies"].get<uint32_t>();

        heuristicsManager.updateMetrics(metrics);
    }

    bool getIsActive() { std::lock_guard<std::mutex> lock(stateMutex); return isActive; }
    std::string getActiveRecipe() { std::lock_guard<std::mutex> lock(stateMutex); return activeRecipe; }
    uint32_t getActiveEpoch() { std::lock_guard<std::mutex> lock(stateMutex); return currentEpoch; }

    std::string evaluateAndSwitch() {
        OperationalMode newMode = heuristicsManager.evaluateThreatAndSwitchMode();
        std::string recipe;
        switch (newMode) {
            case OperationalMode::STANDARD: recipe = "CHAOS_ONLY"; break;
            case OperationalMode::HARDENED: recipe = "FULL_STACK"; break;
            case OperationalMode::CHACHA20_AEAD: recipe = "CHACHA_HEAVY"; break;
            case OperationalMode::SALSA20_AEAD: recipe = "SALSA_LIGHT"; break;
            default: recipe = "CHAOS_ONLY";
        }
        std::string current = getActiveRecipe();
        if (recipe == current) {
            std::cout << "[ZTM][HEURISTICS] No switch: targetRecipe == activeRecipe (" << recipe << ")" << std::endl;
            return "";
        }
        std::string reason = heuristicsManager.getModeDescription(newMode);
        if (!getIsActive()) {
            std::cout << "[ZTM][HEURISTICS] No switch: ZTM not active (wanted " << recipe << " from mode " << (int)newMode << ")" << std::endl;
            return "";
        }
        std::string pid = proposeSwitchToDevice(recipe, reason, broadcastFn ? broadcastFn : [](const nlohmann::json&){});
        if (pid.empty()) {
            std::cout << "[ZTM][HEURISTICS] No switch: proposeSwitchToDevice rejected (cooldown or invalid) for recipe " << recipe << std::endl;
            return "";
        }
        std::cout << "[ZTM][HEURISTICS] Switch proposed by heuristics: " << current << " → " << recipe
                  << " reason=" << reason << " proposalId=" << pid << std::endl;
        return recipe;
    }

    std::pair<std::string, std::string> getRecommendedSwitch() {
        std::lock_guard<std::mutex> lock(stateMutex);
        OperationalMode newMode = heuristicsManager.evaluateThreatAndSwitchMode();
        std::string recipe;
        switch (newMode) {
            case OperationalMode::STANDARD: recipe = "CHAOS_ONLY"; break;
            case OperationalMode::HARDENED: recipe = "FULL_STACK"; break;
            case OperationalMode::CHACHA20_AEAD: recipe = "CHACHA_HEAVY"; break;
            case OperationalMode::SALSA20_AEAD: recipe = "SALSA_LIGHT"; break;
            default: recipe = "CHAOS_ONLY";
        }
        if (recipe == activeRecipe) return {"", ""};
        uint64_t now = currentTimeMs();
        if (now - lastRecipeSwitchTime < MIN_SWITCH_INTERVAL_MS) return {"", ""};
        return {recipe, heuristicsManager.getModeDescription(newMode)};
    }

    void startAdaptiveLoop(std::function<void(const nlohmann::json&)> fn) {
        if (adaptiveLoopRunning.load()) return;
        setBroadcastFn(fn);
        adaptiveLoopRunning.store(true);
        adaptiveThread = std::thread([this, fn]() {
            while (adaptiveLoopRunning.load()) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
                if (getIsActive()) {
                    tickTimeoutsAndRetries(fn);
                    auto [newRecipe, reason] = getRecommendedSwitch();
                    if (!newRecipe.empty())
                        proposeSwitchToDevice(newRecipe, reason, fn);
                }
                if (fn) fn(getHeuristics());
            }
        });
    }

    void stopAdaptiveLoop() {
        adaptiveLoopRunning.store(false);
        if (adaptiveThread.joinable()) adaptiveThread.join();
    }
};

// ============================================================================
// Handlers and dispatcher
// ============================================================================

inline nlohmann::json handleZTMActivate(const nlohmann::json& msg) {
    std::string passkey = msg.value("passkey", "");
    ZTMStateManager* ztm = ZTMStateManager::getInstance();
    if (!ztm->verifyPasskey(passkey)) {
        return {{"type", "ztm_activation_failed"}, {"success", false}, {"message", "Invalid passkey"}, {"serverTime", ZTMStateManager::currentTimeMs()}};
    }
    ztm->activate(msg.value("sessionKey", ""), msg.value("ephemeralIdentity", ""));
    nlohmann::json response = ztm->getStatus();
    response["type"] = "ztm_activation_acknowledged";
    response["success"] = true;
    response["message"] = "Zero Trust Mode activated successfully";
    return response;
}

inline nlohmann::json handleZTMDeactivate(const nlohmann::json& msg) {
    ZTMStateManager::getInstance()->deactivate();
    return {{"type", "ztm_status_update"}, {"active", false}, {"message", "Zero Trust Mode deactivated"}, {"serverTime", ZTMStateManager::currentTimeMs()}};
}

inline nlohmann::json handleGetZTMStatus(const nlohmann::json& msg) {
    return ZTMStateManager::getInstance()->getStatus();
}

inline nlohmann::json handleAdaptiveSwitch(const nlohmann::json& msg,
    const std::function<void(const nlohmann::json&)>& broadcastFn) {
    std::string recipe = msg.value("recipe", "");
    std::string reason = msg.value("reason", "Manual switch request");
    ZTMStateManager* ztm = ZTMStateManager::getInstance();
    if (!ztm->getIsActive()) {
        return {{"type", "adaptive_switch_failed"}, {"success", false}, {"message", "ZTM is not active"}, {"serverTime", ZTMStateManager::currentTimeMs()}};
    }
    static const std::vector<std::string> validRecipes = {"CHAOS_ONLY", "SALSA_LIGHT", "CHACHA_HEAVY", "FULL_STACK", "STREAM_FOCUS"};
    bool valid = false;
    for (const auto& r : validRecipes) { if (r == recipe) { valid = true; break; } }
    if (!valid) {
        return {{"type", "adaptive_switch_failed"}, {"success", false}, {"message", "Invalid recipe"}, {"requestedRecipe", recipe}, {"serverTime", ZTMStateManager::currentTimeMs()}};
    }
    std::string proposalId = ztm->proposeSwitchToDevice(recipe, reason, broadcastFn);
    if (proposalId.empty()) {
        return {{"type", "adaptive_switch_failed"}, {"success", false}, {"message", "Propose failed or cooldown"}, {"serverTime", ZTMStateManager::currentTimeMs()}};
    }
    return {
        {"type", "adaptive_switch_acknowledged"}, {"success", true}, {"recipe", recipe}, {"reason", reason},
        {"pending", true}, {"proposalId", proposalId}, {"serverTime", ZTMStateManager::currentTimeMs()}
    };
}

inline nlohmann::json handleGetHeuristics(const nlohmann::json& msg) {
    return ZTMStateManager::getInstance()->getHeuristics();
}

inline nlohmann::json handleSimulateHeuristics(const nlohmann::json& msg) {
    ZTMStateManager* ztm = ZTMStateManager::getInstance();
    if (msg.contains("values")) ztm->simulateHeuristics(msg["values"]);
    ztm->evaluateAndSwitch();
    nlohmann::json response = ztm->getHeuristics();
    response["type"] = "simulate_heuristics_response";
    response["simulated"] = true;
    return response;
}

inline bool dispatchZTMMessage(
    const std::string& msgType, const nlohmann::json& msg,
    crow::websocket::connection& conn,
    std::function<void(const nlohmann::json&)> broadcastFn) {
    nlohmann::json response;
    bool handled = true;
    bool shouldBroadcast = false;

    if (msgType == "ztm_activate_request") {
        response = handleZTMActivate(msg);
        shouldBroadcast = response.value("success", false);
        if (response.value("success", false))
            ZTMStateManager::getInstance()->startAdaptiveLoop(broadcastFn);
    }
    else if (msgType == "ztm_deactivate_request") {
        response = handleZTMDeactivate(msg);
        shouldBroadcast = true;
        ZTMStateManager::getInstance()->stopAdaptiveLoop();
    }
    else if (msgType == "get_ztm_status") {
        response = handleGetZTMStatus(msg);
    }
    else if (msgType == "adaptive_switch_request") {
        response = handleAdaptiveSwitch(msg, broadcastFn);
        shouldBroadcast = response.value("success", false);
        // Note: [ZTM][SEND_PROPOSE] is already logged inside proposeSwitchToDevice
    }
    else if (msgType == "get_heuristics") {
        response = handleGetHeuristics(msg);
    }
    else if (msgType == "simulate_heuristics") {
        response = handleSimulateHeuristics(msg);
        shouldBroadcast = true;
    }
    else if (msgType == "switch_ack") {
        ZTMStateManager* ztm = ZTMStateManager::getInstance();
        ztm->handleSwitchAck(msg, broadcastFn);
        // Extract proposalId from payload or flat message
        std::string proposalId;
        if (msg.contains("payload") && msg["payload"].contains("proposalId")) {
            proposalId = msg["payload"]["proposalId"].get<std::string>();
        } else {
            proposalId = msg.value("proposalId", "");
        }
        response = {{"type", "switch_ack_received"}, {"proposalId", proposalId}, {"serverTime", ZTMStateManager::currentTimeMs()}};
    }
    else if (msgType == "switch_done") {
        ZTMStateManager* ztm = ZTMStateManager::getInstance();
        bool ok = ztm->handleSwitchDone(msg);
        // Extract proposalId from payload or flat message
        std::string proposalId;
        if (msg.contains("payload") && msg["payload"].contains("proposalId")) {
            proposalId = msg["payload"]["proposalId"].get<std::string>();
        } else {
            proposalId = msg.value("proposalId", "");
        }
        response = {{"type", "switch_committed"}, {"proposalId", proposalId}, {"status", ok ? "committed" : "rejected"}, {"serverTime", ZTMStateManager::currentTimeMs()}};
        shouldBroadcast = true;
    }
    else if (msgType == "switch_nack") {
        ZTMStateManager* ztm = ZTMStateManager::getInstance();
        ztm->handleSwitchNack(msg);
        // Extract proposalId from payload or flat message
        std::string proposalId;
        if (msg.contains("payload") && msg["payload"].contains("proposalId")) {
            proposalId = msg["payload"]["proposalId"].get<std::string>();
        } else {
            proposalId = msg.value("proposalId", "");
        }
        response = {{"type", "switch_nack_received"}, {"proposalId", proposalId}, {"serverTime", ZTMStateManager::currentTimeMs()}};
    }
    else if (msgType == "CONTROL_SYNC_REQUEST") {
        response = ZTMStateManager::getInstance()->getStatus();
        response["type"] = "sync_response";
        response["status"] = "no_resend"; // Two-Phase: no single pending; device must wait for new propose
    }
    else {
        handled = false;
    }

    if (handled) {
        if (shouldBroadcast) broadcastFn(response);
        else conn.send_text(response.dump());
    }
    return handled;
}

// Static member definitions
inline ZTMStateManager* ZTMStateManager::instance = nullptr;
inline std::mutex ZTMStateManager::instanceMutex;
