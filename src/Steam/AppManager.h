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
    void RemoveUnlockedApp(uint32_t appId);
    bool IsAppUnlocked(uint32_t appId) const;
    void GetUnlockedApps(std::vector<uint32_t>& out) const;

    void SetAppDLCs(uint32_t appId, const std::vector<uint32_t>& dlcs);
    bool IsDLCUnlocked(uint32_t appId, uint32_t dlcId) const;

    void SetDepotKey(uint32_t depotId, const std::vector<uint8_t>& keyBytes);
    bool GetDepotKey(uint32_t depotId, std::vector<uint8_t>& outKey) const;

    void Clear();
    size_t GetUnlockedCount() const;

private:
    AppManager() = default;
    mutable std::mutex m_mutex;
    std::unordered_set<uint32_t> m_unlockedApps;
    std::unordered_map<uint32_t, std::unordered_set<uint32_t>> m_appDLCs;
    std::unordered_map<uint32_t, std::vector<uint8_t>> m_depotKeys;
};

} // namespace IceBreaker
