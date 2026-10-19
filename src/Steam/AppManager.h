#pragma once
#include <cstdint>
#include <unordered_set>
#include <unordered_map>
#include <string>
#include <vector>
#include <mutex>

namespace IceBreaker {

struct DLCInfo {
    uint32_t appId;
    bool available;
};

class AppManager {
public:
    static AppManager& Get();

    void AddUnlockedApp(uint32_t appId);
    bool IsAppUnlocked(uint32_t appId) const;

    void SetAppDLCs(uint32_t appId, const std::vector<uint32_t>& dlcs);
    bool IsDLCUnlocked(uint32_t appId, uint32_t dlcId) const;

    void Clear();
    size_t GetUnlockedCount() const;

private:
    AppManager() = default;
    mutable std::mutex m_mutex;
    std::unordered_set<uint32_t> m_unlockedApps;
    std::unordered_map<uint32_t, std::unordered_set<uint32_t>> m_appDLCs;
};

} // namespace IceBreaker
