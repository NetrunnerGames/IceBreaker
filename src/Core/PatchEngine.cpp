#include "PatchEngine.h"
#include "Scanner.h"
#include "Patterns.h"
#include "HookManager.h"
#include "../Steam/AppManager.h"
#include "../Steam/Interfaces.h"
#include <sstream>
#include <cstdint>
#include <vector>
#include <cstring>

namespace IceBreaker {

std::unordered_map<std::string, uintptr_t> PatchEngine::s_resolved;

uintptr_t PatchEngine::ResolvedAddress(const std::string& name) {
    auto it = s_resolved.find(name);
    return it != s_resolved.end() ? it->second : 0;
}

void PatchEngine::CacheResolved(const std::string& name, uintptr_t addr) {
    if (addr) s_resolved[name] = addr;
}

uintptr_t PatchEngine::ClientBase() {
    static uintptr_t base = reinterpret_cast<uintptr_t>(GetModuleHandleW(L"steamclient64.dll"));
    return base;
}

uintptr_t PatchEngine::UIBase() {
    return reinterpret_cast<uintptr_t>(GetModuleHandleW(L"steamui.dll"));
}

static std::string Hex(uintptr_t addr) {
    std::ostringstream out;
    out << "0x" << std::hex << addr;
    return out.str();
}

// ── Active Steam Account ID Resolution ────────────────────────────────
// Parses the active user's 32-bit AccountID from Steam's configuration files
// (e.g. loginusers.vdf / userdata directory) so that AppOwnership can explicitly
// assign ownership to the local user. When SteamId32 matches the current user,
// Steam's CEF UI suppresses the "From your Steam Family library" badge entirely.
static uint32_t GetActiveAccountID() {
    static uint32_t s_cachedAccountId = 0;
    if (s_cachedAccountId != 0) return s_cachedAccountId;

    // 1. Try reading SteamPath from Registry
    wchar_t steamPath[MAX_PATH] = { 0 };
    DWORD pathSize = sizeof(steamPath);
    if (RegGetValueW(HKEY_CURRENT_USER, L"Software\\Valve\\Steam", L"SteamPath",
                     RRF_RT_REG_SZ, nullptr, steamPath, &pathSize) == ERROR_SUCCESS) {
        std::wstring loginUsersPath = std::wstring(steamPath) + L"\\config\\loginusers.vdf";
        HANDLE hFile = CreateFileW(loginUsersPath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                   nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile != INVALID_HANDLE_VALUE) {
            DWORD fileSize = GetFileSize(hFile, nullptr);
            if (fileSize > 0 && fileSize < 1024 * 1024) { // safety limit 1MB
                std::string content(fileSize, '\0');
                DWORD bytesRead = 0;
                if (ReadFile(hFile, &content[0], fileSize, &bytesRead, nullptr)) {
                    // Look for 7656119xxxxxxxxxx SteamID64 blocks
                    size_t pos = 0;
                    while ((pos = content.find("\"7656119", pos)) != std::string::npos) {
                        size_t endQuote = content.find('"', pos + 1);
                        if (endQuote != std::string::npos) {
                            std::string idStr = content.substr(pos + 1, endQuote - (pos + 1));
                            // Check if this block has "AutoLogin" "1" or "MostRecent" "1"
                            size_t blockEnd = content.find('}', endQuote);
                            std::string block = (blockEnd != std::string::npos)
                                ? content.substr(endQuote, blockEnd - endQuote)
                                : content.substr(endQuote, 500);

                            bool isRecent = (block.find("\"AutoLogin\"\t\t\"1\"") != std::string::npos ||
                                             block.find("\"AutoLogin\"\t\"1\"") != std::string::npos ||
                                             block.find("\"AutoLogin\" \"1\"") != std::string::npos ||
                                             block.find("\"MostRecent\"\t\t\"1\"") != std::string::npos ||
                                             block.find("\"MostRecent\"\t\"1\"") != std::string::npos ||
                                             block.find("\"MostRecent\" \"1\"") != std::string::npos);

                            if (isRecent || s_cachedAccountId == 0) {
                                try {
                                    uint64_t steamId64 = std::stoull(idStr);
                                    if (steamId64 > 76561197960265728ULL) {
                                        s_cachedAccountId = static_cast<uint32_t>(steamId64 - 76561197960265728ULL);
                                        if (isRecent) break;
                                    }
                                } catch (...) {}
                            }
                        }
                        pos = endQuote;
                    }
                }
            }
            CloseHandle(hFile);
        }
    }

    // 2. Fallback: inspect userdata folder
    if (s_cachedAccountId == 0 && wcslen(steamPath) > 0) {
        std::wstring userDataPath = std::wstring(steamPath) + L"\\userdata\\*";
        WIN32_FIND_DATAW fd;
        HANDLE hFind = FindFirstFileW(userDataPath.c_str(), &fd);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
                    fd.cFileName[0] != L'.') {
                    wchar_t* endPtr = nullptr;
                    unsigned long id = wcstoul(fd.cFileName, &endPtr, 10);
                    if (id > 0 && endPtr && *endPtr == L'\0') {
                        s_cachedAccountId = static_cast<uint32_t>(id);
                        break;
                    }
                }
            } while (FindNextFileW(hFind, &fd));
            FindClose(hFind);
        }
    }

    return s_cachedAccountId;
}

// ── Valve internal structures for Package 0 injection ─────────────────────────
template<typename T>
struct CUtlMemory {
    T* m_pMemory;
    uint32_t m_nAllocationCount;
    uint32_t m_nGrowSize;
};

template<typename T>
struct CUtlVector {
    CUtlMemory<T> m_Memory;
    uint32_t m_Size;

    void FastRemove(uint32_t elem) {
        if (elem < m_Size) {
            if (elem != m_Size - 1)
                m_Memory.m_pMemory[elem] = m_Memory.m_pMemory[m_Size - 1];
            --m_Size;
        }
    }

    bool FindAndFastRemove(const T& src) {
        for (uint32_t i = 0; i < m_Size; ++i) {
            if (m_Memory.m_pMemory[i] == src) {
                FastRemove(i);
                return true;
            }
        }
        return false;
    }
};

struct PackageInfo {
    uint32_t PackageId;
    int32_t ChangeNumber;
    uint64_t PICS_token;
    int32_t BillingType;
    int32_t LicenseType;
    int32_t Status; // 0 = Available
    uint8_t SHA_1_Hash[20];
    void* pPackageInfoNodeBegin;
    void* pExtendNodeBegin;
    CUtlVector<uint32_t> AppIdVec;
    CUtlVector<uint32_t> DepotIdVec;
};

// ── steamclient64: function pointers for package manipulation ──────────────────
typedef void* (*pfnCUtlMemoryGrow_t)(void* pVec, int grow_size);
typedef int64_t (*pfnMarkLicenseAsChanged_t)(void* pCUser, uint32_t packageId, bool bChanged);
typedef bool (*pfnProcessPendingLicenseUpdates_t)(void* pCUser);
typedef PackageInfo* (__fastcall *pfnGetPackageInfo_t)(void* pThis, uint32_t packageId, uint64_t accessToken);

static pfnCUtlMemoryGrow_t oCUtlMemoryGrow = nullptr;
static pfnMarkLicenseAsChanged_t oMarkLicenseAsChanged = nullptr;
static pfnProcessPendingLicenseUpdates_t oProcessPendingLicenseUpdates = nullptr;
static pfnGetPackageInfo_t oGetPackageInfo = nullptr;

static void* g_pCPackageInfo = nullptr;
static void* g_pCUser = nullptr;
static PackageInfo* g_pInjectedPackageInfo = nullptr;
static bool g_licenseInitialized = false;
static bool g_licenseRefreshPending = false;

constexpr uint32_t kInjectedPackageId = 0;
constexpr uint64_t kInjectedPkgAccessToken = 10660652434190618804ull;

static bool MarkLicenseAsChangedAndProcessUpdates() {
    if (!g_pCUser || !oMarkLicenseAsChanged || !oProcessPendingLicenseUpdates) {
        return false;
    }
    oMarkLicenseAsChanged(g_pCUser, kInjectedPackageId, true);
    oProcessPendingLicenseUpdates(g_pCUser);
    HookManager::Log("MarkLicenseAsChanged: updated package " + std::to_string(kInjectedPackageId));
    return true;
}

static bool InitFakeLicenseOnce(PackageInfo* pPkg) {
    if (pPkg->Status != 0) { // EPackageStatus::Available == 0
        HookManager::Log("InitFakeLicenseOnce: package status is not Available (" + std::to_string(pPkg->Status) + ")");
        return false;
    }

    std::vector<uint32_t> appIds;
    AppManager::Get().GetUnlockedApps(appIds);
    if (!appIds.empty() && oCUtlMemoryGrow) {
        uint32_t oldSize = pPkg->AppIdVec.m_Size;
        uint32_t numToAdd = static_cast<uint32_t>(appIds.size());
        oCUtlMemoryGrow(&pPkg->AppIdVec, numToAdd);
        for (uint32_t i = 0; i < numToAdd; ++i) {
            pPkg->AppIdVec.m_Memory.m_pMemory[oldSize + i] = appIds[i];
        }
        HookManager::Log("InitFakeLicense: injected " + std::to_string(numToAdd) + " apps into Package 0");
    }

    g_licenseInitialized = true;
    g_licenseRefreshPending = true;
    if (MarkLicenseAsChangedAndProcessUpdates()) {
        g_licenseRefreshPending = false;
    }
    return true;
}

static bool TryInitFakeLicenseOnce() {
    if (g_licenseInitialized) return true;
    if (g_pCPackageInfo && oGetPackageInfo) {
        PackageInfo* pPkg = oGetPackageInfo(g_pCPackageInfo, kInjectedPackageId, kInjectedPkgAccessToken);
        if (!pPkg) {
            HookManager::Log("TryInitFakeLicenseOnce: GetPackageInfo returned null for package 0");
            return false;
        }
        if (!g_pInjectedPackageInfo) g_pInjectedPackageInfo = pPkg;
        return InitFakeLicenseOnce(pPkg);
    }
    return false;
}

void PatchEngine::NotifyLicenseChanged() {
    PackageInfo* pPkg = g_pInjectedPackageInfo;
    if (!pPkg || !oCUtlMemoryGrow) return;

    std::vector<uint32_t> appIds;
    AppManager::Get().GetUnlockedApps(appIds);
    if (appIds.empty()) return;

    // Fast-append missing appIds
    std::unordered_set<uint32_t> existing;
    for (uint32_t i = 0; i < pPkg->AppIdVec.m_Size; ++i) {
        existing.insert(pPkg->AppIdVec.m_Memory.m_pMemory[i]);
    }

    std::vector<uint32_t> toAdd;
    for (uint32_t id : appIds) {
        if (!existing.count(id)) toAdd.push_back(id);
    }

    if (!toAdd.empty()) {
        uint32_t oldSize = pPkg->AppIdVec.m_Size;
        uint32_t numToAdd = static_cast<uint32_t>(toAdd.size());
        oCUtlMemoryGrow(&pPkg->AppIdVec, numToAdd);
        for (uint32_t i = 0; i < numToAdd; ++i) {
            pPkg->AppIdVec.m_Memory.m_pMemory[oldSize + i] = toAdd[i];
        }
        HookManager::Log("NotifyLicenseChanged: added " + std::to_string(numToAdd) + " apps to Package 0");
    }

    MarkLicenseAsChangedAndProcessUpdates();
}

// ── steamclient64: CheckAppOwnership hook ─────────────────────────────
// Full AppOwnership layout matching steamclient64.dll.
// Setting bBorrowed and bFamilyShared to false prevents Steam from flagging
// unlocked games with "From your Steam Family library".
struct AppOwnership {
    uint32_t PackageId;
    uint32_t ReleaseState;
    uint32_t SteamId32;
    uint32_t MasterSubscriptionAppID;
    uint32_t TrialSeconds;
    bool bSubscribed;
    bool bOccupied;
    bool bTemporarilyUnavailable;
    bool bFreeLicense;
    bool bBorrowed;
    bool bFamilyShared;
    bool bGuestPass;
    bool bLicenseLocked;
    bool bLicensePending;
};

typedef bool (*pfnCheckAppOwnership)(void* pThis, uint32_t appId, AppOwnership* pOwnership);
static pfnCheckAppOwnership oCheckAppOwnership = nullptr;

static bool Hook_CheckAppOwnership(void* pThis, uint32_t appId, AppOwnership* pOwn) {
    if (!g_pCUser) {
        g_pCUser = pThis;
        HookManager::Log("CheckAppOwnership: captured CUser");
        if (g_licenseRefreshPending) {
            MarkLicenseAsChangedAndProcessUpdates();
            g_licenseRefreshPending = false;
        }
    }

    bool result = oCheckAppOwnership ? oCheckAppOwnership(pThis, appId, pOwn) : false;

    if (AppManager::Get().IsAppUnlocked(appId)) {
        if (pOwn) {
            pOwn->PackageId = kInjectedPackageId;
            pOwn->ReleaseState = 1;
            pOwn->SteamId32 = GetActiveAccountID();
            pOwn->MasterSubscriptionAppID = 0;
            pOwn->TrialSeconds = 0;
            pOwn->bSubscribed = true;
            pOwn->bOccupied = false;
            pOwn->bTemporarilyUnavailable = false;
            pOwn->bFreeLicense = false;
            pOwn->bBorrowed = false;
            pOwn->bFamilyShared = false;
            pOwn->bGuestPass = false;
            pOwn->bLicenseLocked = false;
            pOwn->bLicensePending = false;
            return true;
        }
    }
    return result;
}

// ── steamclient64: GetPackageInfo hook for capturing CPackageInfo ─────
static PackageInfo* Hook_GetPackageInfo(void* pThis, uint32_t packageId, uint64_t accessToken) {
    if (!g_pCPackageInfo) {
        g_pCPackageInfo = pThis;
        HookManager::Log("GetPackageInfo: captured CPackageInfo");
        TryInitFakeLicenseOnce();
    }
    return oGetPackageInfo ? oGetPackageInfo(pThis, packageId, accessToken) : nullptr;
}

// ── steamclient64: ConfigStoreGetBinary hook for depot decryption keys ─
typedef int32_t (*pfnConfigStoreGetBinary_t)(void* pObject, int32_t eConfigStore, const char* KeyName, char* Key, uint32_t KeySize);
static pfnConfigStoreGetBinary_t oConfigStoreGetBinary = nullptr;

static int32_t Hook_ConfigStoreGetBinary(void* pObject, int32_t eConfigStore, const char* KeyName, char* Key, uint32_t KeySize) {
    if (KeyName) {
        std::string name(KeyName);
        // Expected shape: ".../<DepotId>\DecryptionKey" or "<DepotId>\DecryptionKey"
        size_t last = name.find("\\DecryptionKey");
        if (last != std::string::npos) {
            size_t start = name.find_last_of("\\", last - 1);
            size_t idStart = (start != std::string::npos) ? (start + 1) : 0;
            std::string idStr = name.substr(idStart, last - idStart);
            try {
                uint32_t depotId = std::stoul(idStr);
                std::vector<uint8_t> keyBytes;
                if (AppManager::Get().GetDepotKey(depotId, keyBytes)) {
                    if (KeySize >= keyBytes.size()) {
                        memcpy(Key, keyBytes.data(), keyBytes.size());
                        HookManager::Log("ConfigStoreGetBinary: served decryption key for depot " + std::to_string(depotId));
                        return static_cast<int32_t>(keyBytes.size());
                    }
                }
            } catch (...) {}
        }
    }

    return oConfigStoreGetBinary ? oConfigStoreGetBinary(pObject, eConfigStore, KeyName, Key, KeySize) : 0;
}

// ── steamui.dll: library visibility hook ──────────────────────────────
typedef bool (*pfnShouldShowAppInLibrary)(void* pThis, uint32_t appId);
static pfnShouldShowAppInLibrary oShouldShowAppInLibrary = nullptr;

static bool Hook_ShouldShowAppInLibrary(void* pThis, uint32_t appId) {
    if (AppManager::Get().IsAppUnlocked(appId)) {
        return true;
    }
    if (oShouldShowAppInLibrary) {
        return oShouldShowAppInLibrary(pThis, appId);
    }
    return true;
}

// ── resolution bookkeeping ────────────────────────────────────────────
static void Resolve(const PatternDefinition& pat, uintptr_t base, const char* tag) {
    if (PatchEngine::ResolvedAddress(pat.name)) return;
    uintptr_t addr = Scanner::ScanModule(reinterpret_cast<HMODULE>(base), pat.pattern);
    if (!addr) {
        HookManager::Log(std::string(tag) + ": pattern not matched: " + pat.name + " (non-fatal)");
        return;
    }
    PatchEngine::CacheResolved(pat.name, addr);
    HookManager::Log(std::string(tag) + ": found " + pat.name + " at " + Hex(addr));
}

void PatchEngine::ApplyInMemoryPatches() {
    const uintptr_t ui = UIBase();
    const uintptr_t client = ClientBase();
    HookManager::Log("Scanning in-memory patterns (steamui=" + Hex(ui) + " steamclient64=" + Hex(client) + ")");

    if (ui) {
        for (const auto& pat : g_SteamUIPatterns) {
            Resolve(pat, ui, "steamui");
        }
        if (auto addr = ResolvedAddress("ShouldShowAppInLibrary")) {
            HookManager::CreateHook(reinterpret_cast<void*>(addr),
                                    reinterpret_cast<void*>(&Hook_ShouldShowAppInLibrary),
                                    reinterpret_cast<void**>(&oShouldShowAppInLibrary),
                                    "ShouldShowAppInLibrary");
        }
    }

    if (client) {
        for (const auto& pat : g_SteamClientPatterns) {
            Resolve(pat, client, "steamclient64");
        }
        if (auto addr = ResolvedAddress("CheckAppOwnership")) {
            HookManager::CreateHook(reinterpret_cast<void*>(addr),
                                    reinterpret_cast<void*>(&Hook_CheckAppOwnership),
                                    reinterpret_cast<void**>(&oCheckAppOwnership),
                                    "CheckAppOwnership");
            Interfaces::SetOwnershipAnchor(reinterpret_cast<void*>(addr));
        }
        if (auto addr = ResolvedAddress("GetPackageInfo")) {
            HookManager::CreateHook(reinterpret_cast<void*>(addr),
                                    reinterpret_cast<void*>(&Hook_GetPackageInfo),
                                    reinterpret_cast<void**>(&oGetPackageInfo),
                                    "GetPackageInfo");
        }
        if (auto addr = ResolvedAddress("ConfigStoreGetBinary")) {
            HookManager::CreateHook(reinterpret_cast<void*>(addr),
                                    reinterpret_cast<void*>(&Hook_ConfigStoreGetBinary),
                                    reinterpret_cast<void**>(&oConfigStoreGetBinary),
                                    "ConfigStoreGetBinary");
        }
        if (auto addr = ResolvedAddress("MarkLicenseAsChanged")) {
            oMarkLicenseAsChanged = reinterpret_cast<pfnMarkLicenseAsChanged_t>(addr);
        }
        if (auto addr = ResolvedAddress("ProcessPendingLicenseUpdates")) {
            oProcessPendingLicenseUpdates = reinterpret_cast<pfnProcessPendingLicenseUpdates_t>(addr);
        }
        if (auto addr = ResolvedAddress("CUtlMemoryGrow")) {
            oCUtlMemoryGrow = reinterpret_cast<pfnCUtlMemoryGrow_t>(addr);
        }
    }

    HookManager::Log("In-memory patching complete. Resolved " +
                     std::to_string(s_resolved.size()) + " patterns.");
}

} // namespace IceBreaker
