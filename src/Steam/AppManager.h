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

    void AddUnlockedApp(uint32_t appId, uint32_t packageId = 0);
    void RemoveUnlockedApp(uint32_t appId);
    bool IsAppUnlocked(uint32_t appId) const;
    void GetUnlockedApps(std::vector<uint32_t>& out) const;
    uint32_t GetAppPackageId(uint32_t appId) const;
    void GetPackages(std::unordered_map<uint32_t, std::vector<uint32_t>>& out) const;

    void SetAppDLCs(uint32_t appId, const std::vector<uint32_t>& dlcs);
    bool IsDLCUnlocked(uint32_t appId, uint32_t dlcId) const;

    void SetDepotKey(uint32_t depotId, const std::vector<uint8_t>& keyBytes);
    bool GetDepotKey(uint32_t depotId, std::vector<uint8_t>& outKey) const;

    // PICS access tokens (from addtoken(id, "token") lua lines). Used to patch outgoing
    // CMsgClientPICSProductInfoRequest so Steam actually resolves appinfo for injected app ids.
    void SetAccessToken(uint32_t appId, uint64_t token);
    bool GetAccessToken(uint32_t appId, uint64_t& out) const;
    bool HasAnyAccessToken() const;

    // Apps Steam itself reported as genuinely owned (CheckAppOwnership returned true with the app
    // present in more than one real package). Spoofing is skipped for these, mirroring OpenSteamTool.
    void MarkOwned(uint32_t appId);
    bool IsMarkedOwned(uint32_t appId) const;

    void Clear();
    size_t GetUnlockedCount() const;

    // Diff-based reconciliation: atomically swaps in newly scanned state, returns whether apps/packages changed
    bool ReconcileState(const std::unordered_map<uint32_t, uint32_t>& newAppToPackage,
                        const std::unordered_map<uint32_t, std::unordered_set<uint32_t>>& newAppDLCs,
                        const std::unordered_map<uint32_t, std::vector<uint8_t>>& newDepotKeys,
                        const std::unordered_map<uint32_t, uint64_t>& newAccessTokens);

private:
    AppManager() = default;
    mutable std::mutex m_mutex;
    std::unordered_set<uint32_t> m_unlockedApps;
    std::unordered_map<uint32_t, uint32_t> m_appToPackage;
    std::unordered_map<uint32_t, std::unordered_set<uint32_t>> m_packageToApps;
    std::unordered_map<uint32_t, std::unordered_set<uint32_t>> m_appDLCs;
    std::unordered_map<uint32_t, std::vector<uint8_t>> m_depotKeys;
    std::unordered_map<uint32_t, uint64_t> m_accessTokens;
    std::unordered_set<uint32_t> m_ownedApps;
};

} // namespace IceBreaker
