#include "AppManager.h"

namespace IceBreaker {

AppManager& AppManager::Get() {
    static AppManager instance;
    return instance;
}

void AppManager::AddUnlockedApp(uint32_t appId) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_unlockedApps.insert(appId);
}

void AppManager::RemoveUnlockedApp(uint32_t appId) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_unlockedApps.erase(appId);
}

bool AppManager::IsAppUnlocked(uint32_t appId) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_unlockedApps.find(appId) != m_unlockedApps.end();
}

void AppManager::GetUnlockedApps(std::vector<uint32_t>& out) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    out.assign(m_unlockedApps.begin(), m_unlockedApps.end());
}

void AppManager::SetAppDLCs(uint32_t appId, const std::vector<uint32_t>& dlcs) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto& set = m_appDLCs[appId];
    for (uint32_t dlc : dlcs) {
        set.insert(dlc);
    }
}

bool AppManager::IsDLCUnlocked(uint32_t appId, uint32_t dlcId) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_appDLCs.find(appId);
    if (it != m_appDLCs.end()) {
        return it->second.find(dlcId) != it->second.end();
    }
    // Fallback: if appId itself is unlocked, check if dlcId is directly registered
    return m_unlockedApps.find(dlcId) != m_unlockedApps.end();
}

void AppManager::SetDepotKey(uint32_t depotId, const std::vector<uint8_t>& keyBytes) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_depotKeys[depotId] = keyBytes;
}

bool AppManager::GetDepotKey(uint32_t depotId, std::vector<uint8_t>& outKey) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_depotKeys.find(depotId);
    if (it != m_depotKeys.end()) {
        outKey = it->second;
        return true;
    }
    return false;
}

void AppManager::SetAccessToken(uint32_t appId, uint64_t token) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (token != 0) m_accessTokens[appId] = token;
}

bool AppManager::GetAccessToken(uint32_t appId, uint64_t& out) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_accessTokens.find(appId);
    if (it == m_accessTokens.end()) return false;
    out = it->second;
    return true;
}

bool AppManager::HasAnyAccessToken() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return !m_accessTokens.empty();
}

void AppManager::MarkOwned(uint32_t appId) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_ownedApps.insert(appId);
}

bool AppManager::IsMarkedOwned(uint32_t appId) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_ownedApps.count(appId) != 0;
}

void AppManager::Clear() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_unlockedApps.clear();
    m_appDLCs.clear();
    m_depotKeys.clear();
    m_accessTokens.clear();
    m_ownedApps.clear();
}

size_t AppManager::GetUnlockedCount() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_unlockedApps.size();
}

} // namespace IceBreaker
