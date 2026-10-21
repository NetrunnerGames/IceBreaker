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

void AppManager::Clear() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_unlockedApps.clear();
    m_appDLCs.clear();
}

size_t AppManager::GetUnlockedCount() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_unlockedApps.size();
}

} // namespace IceBreaker
