// server/api/ztm_handlers.h
// Zero Trust Mode WebSocket Handlers
#pragma once

#include <crow.h>
#include <nlohmann/json.hpp>
#include <string>
#include <mutex>
#include <thread>
#include <atomic>
#include <chrono>
#include <fstream>
#include "../../lib/Heuristics_Manager/include/heuristics_manager.h"

// Forward declare EventBus from main.cpp
class EventBus;

// ZTM State Manager - Thread-safe singleton
class ZTMStateManager {
private:
    static ZTMStateManager* instance;
    static std::mutex instanceMutex;
    
    std::mutex stateMutex;
    
    // ZTM State
    bool isActive;
    std::string activeRecipe;
    std::string passkey;
    uint64_t activatedAt;
    std::string lastSwitchReason;
    
    // Heuristics Manager
    HeuristicsManager heuristicsManager;
    
    // Adaptive loop control
    std::atomic<bool> adaptiveLoopRunning;
    std::thread adaptiveThread;
    
    // Cooldown tracking
    uint64_t lastRecipeSwitchTime;
    static const uint64_t MIN_SWITCH_INTERVAL_MS = 5000; // 5 second cooldown
    
    ZTMStateManager() : 
        isActive(false), 
        activeRecipe("CHAOS_ONLY"),
        passkey("1234"),
        activatedAt(0),
        lastSwitchReason(""),
        adaptiveLoopRunning(false),
        lastRecipeSwitchTime(0)
    {
        // Try to load heuristics.json
        heuristicsManager.loadThresholdsFromJSON("../lib/Heuristics_Manager/heuristics.json");
    }
    
public:
    ~ZTMStateManager() {
        stopAdaptiveLoop();
    }
    
    static ZTMStateManager* getInstance() {
        std::lock_guard<std::mutex> lock(instanceMutex);
        if (!instance) {
            instance = new ZTMStateManager();
        }
        return instance;
    }
    
    // Get passkey (from env or default)
    std::string getPasskey() {
        const char* envPasskey = std::getenv("ZTM_PASSKEY");
        return envPasskey ? std::string(envPasskey) : passkey;
    }
    
    // Verify passkey (4-digit numeric)
    bool verifyPasskey(const std::string& inputPasskey) {
        // Validate format: exactly 4 digits
        if (inputPasskey.length() != 4) return false;
        for (char c : inputPasskey) {
            if (!std::isdigit(c)) return false;
        }
        return inputPasskey == getPasskey();
    }
    
    // Activate ZTM
    bool activate(const std::string& sessionKey = "", const std::string& ephemeralId = "") {
        std::lock_guard<std::mutex> lock(stateMutex);
        isActive = true;
        activeRecipe = "CHAOS_ONLY";
        activatedAt = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        lastSwitchReason = "ZTM activated - baseline recipe";
        heuristicsManager.enableZTM(true);
        return true;
    }
    
    // Deactivate ZTM
    void deactivate() {
        std::lock_guard<std::mutex> lock(stateMutex);
        isActive = false;
        heuristicsManager.enableZTM(false);
        lastSwitchReason = "ZTM deactivated";
    }
    
    // Switch recipe
    bool switchRecipe(const std::string& recipe, const std::string& reason) {
        std::lock_guard<std::mutex> lock(stateMutex);
        
        // Validate recipe
        static const std::vector<std::string> validRecipes = {
            "CHAOS_ONLY", "SALSA_LIGHT", "CHACHA_HEAVY", "FULL_STACK", "STREAM_FOCUS"
        };
        
        bool isValid = false;
        for (const auto& r : validRecipes) {
            if (r == recipe) {
                isValid = true;
                break;
            }
        }
        
        if (!isValid) return false;
        
        // Check cooldown
        uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        if (now - lastRecipeSwitchTime < MIN_SWITCH_INTERVAL_MS) {
            return false; // Cooldown not elapsed
        }
        
        activeRecipe = recipe;
        lastSwitchReason = reason;
        lastRecipeSwitchTime = now;
        return true;
    }
    
    // Get current status as JSON
    nlohmann::json getStatus() {
        std::lock_guard<std::mutex> lock(stateMutex);
        HeuristicMetrics metrics = heuristicsManager.getLatestMetrics();
        
        return {
            {"type", "ztm_status_update"},
            {"active", isActive},
            {"recipe", activeRecipe},
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
            {"serverTime", std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count()}
        };
    }
    
    // Get heuristics as JSON
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
            {"serverTime", std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count()}
        };
    }
    
    // Simulate heuristics (for testing)
    void simulateHeuristics(const nlohmann::json& values) {
        HeuristicMetrics metrics;
        
        if (values.contains("entropy")) metrics.entropy = values["entropy"].get<double>();
        if (values.contains("latency")) metrics.latency = values["latency"].get<double>();
        if (values.contains("cpuUsage")) metrics.cpuUsage = values["cpuUsage"].get<double>();
        if (values.contains("hmacFailures")) metrics.hmacFailures = values["hmacFailures"].get<uint32_t>();
        if (values.contains("decryptFailures")) metrics.decryptFailures = values["decryptFailures"].get<uint32_t>();
        if (values.contains("replayAttempts")) metrics.replayAttempts = values["replayAttempts"].get<uint32_t>();
        if (values.contains("malformedPackets")) metrics.malformedPackets = values["malformedPackets"].get<uint32_t>();
        if (values.contains("timingAnomalies")) metrics.timingAnomalies = values["timingAnomalies"].get<uint32_t>();
        
        heuristicsManager.updateMetrics(metrics);
    }
    
    // Record individual metrics
    void recordLatency(double ms) { heuristicsManager.recordLatency(ms); }
    void recordEntropy(double bits) { heuristicsManager.recordEntropy(bits); }
    void recordHmacFailure() { heuristicsManager.recordHmacFailure(); }
    void recordDecryptFailure() { heuristicsManager.recordDecryptFailure(); }
    void recordReplayAttempt() { heuristicsManager.recordReplayAttempt(); }
    
    // Getters
    bool getIsActive() { 
        std::lock_guard<std::mutex> lock(stateMutex);
        return isActive; 
    }
    
    std::string getActiveRecipe() { 
        std::lock_guard<std::mutex> lock(stateMutex);
        return activeRecipe; 
    }
    
    // Evaluate and potentially switch mode
    std::string evaluateAndSwitch() {
        OperationalMode newMode = heuristicsManager.evaluateThreatAndSwitchMode();
        std::string recipe;
        
        switch (newMode) {
            case OperationalMode::STANDARD:
                recipe = "CHAOS_ONLY";
                break;
            case OperationalMode::HARDENED:
                recipe = "CHACHA_HEAVY";
                break;
            case OperationalMode::CHACHA20_AEAD:
                recipe = "FULL_STACK";
                break;
            case OperationalMode::SALSA20_AEAD:
                recipe = "SALSA_LIGHT";
                break;
            default:
                recipe = "CHAOS_ONLY";
        }
        
        std::string currentRecipe = getActiveRecipe();
        if (recipe != currentRecipe) {
            std::string reason = heuristicsManager.getModeDescription(newMode);
            if (switchRecipe(recipe, reason)) {
                return recipe;
            }
        }
        return "";
    }
    
    // Start adaptive monitoring loop
    void startAdaptiveLoop(std::function<void(const nlohmann::json&)> broadcastFn) {
        if (adaptiveLoopRunning.load()) return;
        
        adaptiveLoopRunning.store(true);
        adaptiveThread = std::thread([this, broadcastFn]() {
            while (adaptiveLoopRunning.load()) {
                std::this_thread::sleep_for(std::chrono::seconds(2));
                
                if (!getIsActive()) continue;
                
                // Evaluate and potentially switch
                std::string newRecipe = evaluateAndSwitch();
                
                if (!newRecipe.empty()) {
                    // Broadcast recipe change
                    nlohmann::json update = {
                        {"type", "recipe_update"},
                        {"recipe", newRecipe},
                        {"reason", lastSwitchReason},
                        {"automatic", true},
                        {"serverTime", std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::system_clock::now().time_since_epoch()).count()}
                    };
                    broadcastFn(update);
                }
                
                // Broadcast heuristics update periodically
                broadcastFn(getHeuristics());
            }
        });
    }
    
    void stopAdaptiveLoop() {
        adaptiveLoopRunning.store(false);
        if (adaptiveThread.joinable()) {
            adaptiveThread.join();
        }
    }
};

// Static member definitions
ZTMStateManager* ZTMStateManager::instance = nullptr;
std::mutex ZTMStateManager::instanceMutex;

// ============================================================================
// ZTM WebSocket Message Handlers
// ============================================================================

// Handle ztm_activate_request
inline nlohmann::json handleZTMActivate(const nlohmann::json& msg) {
    std::string passkey = msg.value("passkey", "");
    std::string sessionKey = msg.value("sessionKey", "");
    std::string ephemeralId = msg.value("ephemeralIdentity", "");
    
    ZTMStateManager* ztm = ZTMStateManager::getInstance();
    
    if (!ztm->verifyPasskey(passkey)) {
        return {
            {"type", "ztm_activation_failed"},
            {"success", false},
            {"message", "Invalid passkey"},
            {"serverTime", std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count()}
        };
    }
    
    ztm->activate(sessionKey, ephemeralId);
    
    nlohmann::json response = ztm->getStatus();
    response["type"] = "ztm_activation_acknowledged";
    response["success"] = true;
    response["message"] = "Zero Trust Mode activated successfully";
    
    return response;
}

// Handle ztm_deactivate_request
inline nlohmann::json handleZTMDeactivate(const nlohmann::json& msg) {
    ZTMStateManager* ztm = ZTMStateManager::getInstance();
    ztm->deactivate();
    
    return {
        {"type", "ztm_status_update"},
        {"active", false},
        {"message", "Zero Trust Mode deactivated"},
        {"serverTime", std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count()}
    };
}

// Handle get_ztm_status
inline nlohmann::json handleGetZTMStatus(const nlohmann::json& msg) {
    return ZTMStateManager::getInstance()->getStatus();
}

// Handle adaptive_switch_request
inline nlohmann::json handleAdaptiveSwitch(const nlohmann::json& msg) {
    std::string recipe = msg.value("recipe", "");
    std::string reason = msg.value("reason", "Manual switch request");
    
    ZTMStateManager* ztm = ZTMStateManager::getInstance();
    
    if (!ztm->getIsActive()) {
        return {
            {"type", "adaptive_switch_failed"},
            {"success", false},
            {"message", "ZTM is not active"},
            {"serverTime", std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count()}
        };
    }
    
    if (ztm->switchRecipe(recipe, reason)) {
        return {
            {"type", "adaptive_switch_acknowledged"},
            {"success", true},
            {"recipe", recipe},
            {"reason", reason},
            {"serverTime", std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count()}
        };
    } else {
        return {
            {"type", "adaptive_switch_failed"},
            {"success", false},
            {"message", "Invalid recipe or cooldown active"},
            {"requestedRecipe", recipe},
            {"serverTime", std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count()}
        };
    }
}

// Handle get_heuristics
inline nlohmann::json handleGetHeuristics(const nlohmann::json& msg) {
    return ZTMStateManager::getInstance()->getHeuristics();
}

// Handle simulate_heuristics
inline nlohmann::json handleSimulateHeuristics(const nlohmann::json& msg) {
    ZTMStateManager* ztm = ZTMStateManager::getInstance();
    
    if (msg.contains("values")) {
        ztm->simulateHeuristics(msg["values"]);
    }
    
    // Force evaluation after simulation
    std::string switched = ztm->evaluateAndSwitch();
    
    nlohmann::json response = ztm->getHeuristics();
    response["type"] = "simulate_heuristics_response";
    response["simulated"] = true;
    if (!switched.empty()) {
        response["recipeSwitched"] = switched;
    }
    
    return response;
}

// ============================================================================
// Main dispatcher for ZTM messages
// ============================================================================
inline bool dispatchZTMMessage(
    const std::string& msgType, 
    const nlohmann::json& msg,
    crow::websocket::connection& conn,
    std::function<void(const nlohmann::json&)> broadcastFn
) {
    nlohmann::json response;
    bool handled = true;
    bool shouldBroadcast = false;
    
    if (msgType == "ztm_activate_request") {
        response = handleZTMActivate(msg);
        shouldBroadcast = response.value("success", false);
        
        // Start adaptive loop on activation
        if (response.value("success", false)) {
            ZTMStateManager::getInstance()->startAdaptiveLoop(broadcastFn);
        }
    }
    else if (msgType == "ztm_deactivate_request") {
        response = handleZTMDeactivate(msg);
        shouldBroadcast = true;
        
        // Stop adaptive loop
        ZTMStateManager::getInstance()->stopAdaptiveLoop();
    }
    else if (msgType == "get_ztm_status") {
        response = handleGetZTMStatus(msg);
    }
    else if (msgType == "adaptive_switch_request") {
        response = handleAdaptiveSwitch(msg);
        shouldBroadcast = response.value("success", false);
    }
    else if (msgType == "get_heuristics") {
        response = handleGetHeuristics(msg);
    }
    else if (msgType == "simulate_heuristics") {
        response = handleSimulateHeuristics(msg);
        shouldBroadcast = true;
    }
    else {
        handled = false;
    }
    
    if (handled) {
        if (shouldBroadcast) {
            broadcastFn(response);
        } else {
            conn.send_text(response.dump());
        }
    }
    
    return handled;
}
