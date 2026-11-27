#include "PatchEngine.h"
#include "Scanner.h"
#include "Patterns.h"
#include "OtaClient.h"
#include "HeuristicResolver.h"
#include "RvaCache.h"
#include "HookManager.h"
#include "../Steam/AppManager.h"
#include "../Steam/Interfaces.h"
#include <sstream>
#include <cstdint>
#include <vector>
#include <cstring>
#include <atomic>
#include <mutex>

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
uint32_t PatchEngine::GetActiveAccountID() {
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

enum EPackageStatus : uint32_t {
    PackageStatus_Available = 0,
    PackageStatus_Preorder = 1,
    PackageStatus_Unavailable = 2,
    PackageStatus_Invalid = 3,
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
static std::atomic<bool> g_licenseChangeRequested{ false };
static std::mutex g_licenseMutex;
static std::atomic<int> g_maintenanceAttempts{ 0 };
static bool g_licenseDone = false;
static std::atomic<bool> g_licenseForceReset{ false };

// ── App Download State Sanitizer ──────────────────────────────────────────
// When an app download fails while IceBreaker was not hooked or missing a key,
// Steam writes UpdateResult 6 ("No connection" / Access Denied) and StateFlags 6
// into appmanifest_<appId>.acf, and creates a dead-locked downloading/<appId> folder.
// Even after fixing IceBreaker, Steam locks that app in an exponential backoff error state.
// This function resets the ACF error flags back to 4 (clean state) and cleans empty
// staging residue so Steam immediately requests fresh tokens and downloads normally.
static std::wstring GetSteamRootPath() {
    wchar_t exePath[MAX_PATH] = { 0 };
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    std::wstring path(exePath);
    size_t lastSlash = path.find_last_of(L"\\/");
    if (lastSlash != std::wstring::npos) {
        return path.substr(0, lastSlash);
    }
    return L"";
}

void PatchEngine::SanitizeAppDownloadState(uint32_t appId) {
    if (appId == 0) return;
    std::wstring steamRoot = GetSteamRootPath();
    if (steamRoot.empty()) return;

    std::wstring manifestPath = steamRoot + L"\\steamapps\\appmanifest_" + std::to_wstring(appId) + L".acf";
    std::wstring downloadingDir = steamRoot + L"\\steamapps\\downloading\\" + std::to_wstring(appId);

    // 1. Check if appmanifest exists and has UpdateResult / StateFlags error
    HANDLE hFile = CreateFileW(manifestPath.c_str(), GENERIC_READ | GENERIC_WRITE,
                               FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD size = GetFileSize(hFile, nullptr);
        if (size > 0 && size < 64 * 1024) { // typical ACF is ~1-2 KB
            std::string content(size, '\0');
            DWORD bytesRead = 0;
            if (ReadFile(hFile, &content[0], size, &bytesRead, nullptr)) {
                bool modified = false;

                // Reset UpdateResult "6" (or non-zero error) to "0"
                size_t urPos = content.find("\"UpdateResult\"");
                if (urPos != std::string::npos) {
                    size_t quote1 = content.find('"', urPos + 14);
                    if (quote1 != std::string::npos) {
                        size_t quote2 = content.find('"', quote1 + 1);
                        if (quote2 != std::string::npos) {
                            std::string currentVal = content.substr(quote1 + 1, quote2 - quote1 - 1);
                            if (currentVal == "6" || currentVal == "1" || currentVal == "2") {
                                content.replace(quote1 + 1, quote2 - quote1 - 1, "0");
                                modified = true;
                            }
                        }
                    }
                }

                // If BytesDownloaded is 0 and StateFlags is 6 (error/update required), reset to 4 (Fully Installed)
                size_t bytesDownPos = content.find("\"BytesDownloaded\"\t\t\"0\"");
                if (bytesDownPos == std::string::npos) {
                    bytesDownPos = content.find("\"BytesDownloaded\" \"0\"");
                }
                if (bytesDownPos != std::string::npos) {
                    size_t sfPos = content.find("\"StateFlags\"");
                    if (sfPos != std::string::npos) {
                        size_t q1 = content.find('"', sfPos + 12);
                        if (q1 != std::string::npos) {
                            size_t q2 = content.find('"', q1 + 1);
                            if (q2 != std::string::npos) {
                                std::string sfVal = content.substr(q1 + 1, q2 - q1 - 1);
                                if (sfVal == "6" || sfVal == "1026" || sfVal == "1030") {
                                    content.replace(q1 + 1, q2 - q1 - 1, "4");
                                    modified = true;
                                }
                            }
                        }
                    }
                }

                if (modified) {
                    SetFilePointer(hFile, 0, nullptr, FILE_BEGIN);
                    DWORD bytesWritten = 0;
                    WriteFile(hFile, content.c_str(), static_cast<DWORD>(content.size()), &bytesWritten, nullptr);
                    SetEndOfFile(hFile);
                    HookManager::Log("SanitizeAppDownloadState: purged stale error StateFlags/UpdateResult in appmanifest_" +
                                     std::to_string(appId) + ".acf");
                }
            }
        }
        CloseHandle(hFile);
    }

    // 2. Clean empty downloading folder if 0 bytes
    WIN32_FIND_DATAW fd;
    std::wstring searchPattern = downloadingDir + L"\\*";
    HANDLE hFind = FindFirstFileW(searchPattern.c_str(), &fd);
    bool hasFiles = false;
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (wcscmp(fd.cFileName, L".") != 0 && wcscmp(fd.cFileName, L"..") != 0) {
                hasFiles = true;
                break;
            }
        } while (FindNextFileW(hFind, &fd));
        FindClose(hFind);
    }

    if (!hasFiles && GetFileAttributesW(downloadingDir.c_str()) != INVALID_FILE_ATTRIBUTES) {
        RemoveDirectoryW(downloadingDir.c_str());
    }
}

void PatchEngine::SanitizeAllUnlockedDownloadStates() {
    std::vector<uint32_t> apps;
    AppManager::Get().GetUnlockedApps(apps);
    for (uint32_t appId : apps) {
        SanitizeAppDownloadState(appId);
    }
}

// Defensive validation before touching Valve's package state: if the struct
// layout has drifted or the object looks wrong, refuse to write anything
// (a bad write here corrupts pointer tables and crashes the client later,
// historically as an execute-at-garbage AV during "Loading user data").
static bool ValidatePackageInfo(const PackageInfo* pPkg) {
    if (!pPkg) return false;
    if (pPkg->Status > PackageStatus_Invalid) return false;
    const auto& v = pPkg->AppIdVec;
    if (v.m_Size > v.m_Memory.m_nAllocationCount) return false;
    if (v.m_Memory.m_nAllocationCount > 0x100000u) return false;
    for (uint32_t i = 0; i < v.m_Size && i < 64; ++i) {
        uint32_t id = v.m_Memory.m_pMemory[i];
        if (id == 0 || id == 0xFFFFFFFFu) return false;
    }
    return true;
}

// Appends ids to the license vector only when spare capacity allows. Returns the
// number of ids actually written.
static uint32_t AppendAppIds(PackageInfo* pPkg, const std::vector<uint32_t>& wanted) {
    auto& vec = pPkg->AppIdVec;
    uint32_t written = 0;
    for (uint32_t id : wanted) {
        bool exists = false;
        for (uint32_t i = 0; i < vec.m_Size; ++i)
            if (vec.m_Memory.m_pMemory[i] == id) { exists = true; break; }
        if (exists) continue;
        if (vec.m_Size >= vec.m_Memory.m_nAllocationCount) {
            HookManager::Log("LicenseInjection: vector at capacity (" +
                             std::to_string(vec.m_Size) + "/" +
                             std::to_string(vec.m_Memory.m_nAllocationCount) +
                             "), deferring remaining ids");
            break;
        }
        vec.m_Memory.m_pMemory[vec.m_Size++] = id;
        ++written;
    }
    return written;
}

constexpr uint32_t kInjectedPackageId = 0;
constexpr uint64_t kInjectedPkgAccessToken = 10660652434190618804ull;

// Raw SEH wrappers (no C++ objects in scope — C2712).
static bool MarkLicenseRaw(void* pCUser, uint32_t pkgId) {
    __try {
        oMarkLicenseAsChanged(pCUser, pkgId, true);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

static bool ProcessPendingRaw(void* pCUser) {
    __try {
        oProcessPendingLicenseUpdates(pCUser);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

static bool GrowVectorRaw(CUtlVector<uint32_t>* vec, int growBy) {
    __try {
        oCUtlMemoryGrow(vec, growBy);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// ── Dynamic synthetic package cache for Multi-Package architecture (Solution A)
static std::mutex g_virtualPkgMutex;
static std::unordered_map<uint32_t, PackageInfo> g_virtualPackages;
static std::unordered_map<uint32_t, std::vector<uint32_t>> g_virtualPkgAppStorage;

// ── single-owner license maintenance ─────────────────────────────────
// ALL package-state mutation happens here, always on the thread that invoked
// Hook_CheckAppOwnership (Steam's own license/ownership evaluation thread),
// after the original call has returned. Background threads (IPC RELOAD, file
// watcher, DataJackUI) only raise the request flag — never touch Valve state.
//
// STABILITY RULES learned from crash forensics:
//  * One-shot: the license vector is populated exactly once per process; later
//    Notify requests are ignored until restart. Repeated appends race Steam's
//    own multithreaded license pipeline and corrupt the heap.
//  * Capacity-only: we never grow Valve's vector ourselves. Steam grows it as
//    it processes licenses (observed directly in dumps); we write into spare
//    capacity that exists at that moment, and defer the rest.

// Raw SEH fence without C++ objects (C2712) around the whole maintenance flow.
static bool MaintenanceFence(void* pCPackageInfo, void* pCUser);

static void ConsumeLicenseMaintenance() {
    std::lock_guard<std::mutex> lock(g_licenseMutex);
    if (!g_pCPackageInfo || !oGetPackageInfo || !g_pCUser) return;
    if (g_maintenanceAttempts.load() >= 8) {
        static bool gaveUp = false;
        if (!gaveUp) {
            HookManager::Log("LicenseInjection: giving up after repeated maintenance failures");
            gaveUp = true;
            g_licenseInitialized = true;
            g_licenseChangeRequested.store(false);
        }
        return;
    }
    g_maintenanceAttempts.fetch_add(1);

    if (!MaintenanceFence(g_pCPackageInfo, g_pCUser)) {
        HookManager::Log("LicenseInjection: exception inside license maintenance; steady state entered to protect UI");
        g_licenseDone = true;
        g_licenseInitialized = true;
        g_licenseChangeRequested.store(false);
    } else if (g_licenseDone) {
        g_licenseChangeRequested.store(false);
        g_licenseInitialized = true;
    } else {
        // partial success: keep requesting so we retry as capacity frees up
        g_licenseChangeRequested.store(true);
        g_licenseInitialized = true;
    }
}

static bool MaintenanceBody(void* pCPackageInfo) {
    PackageInfo* pPkg = oGetPackageInfo(pCPackageInfo, kInjectedPackageId, kInjectedPkgAccessToken);
    if (!pPkg) {
        static bool warnedOnce = false;
        if (!warnedOnce) {
            HookManager::Log("LicenseInjection: GetPackageInfo returned null for package 0");
            warnedOnce = true;
        }
        return true; // transient: keep the request pending (g_licenseDone stays false)
    }
    if (!g_pInjectedPackageInfo) g_pInjectedPackageInfo = pPkg;

    if (!ValidatePackageInfo(pPkg)) {
        HookManager::Log("LicenseInjection: package object failed sanity validation; injection disabled for this session");
        g_licenseDone = true;
        return true;
    }

    // Growth strategy: Valve's grow function may be the memory-layer variant
    // (alloc grows, size untouched) or a vector-layer wrapper (alloc AND size
    // grow). Both are accepted, provided postconditions prove every slot we
    // write is backed by allocation:
    //   A) alloc >= oldSize+growBy && size == oldSize  -> append via m_Size++
    //   B) size == oldSize+growBy && alloc >= size     -> fill [oldSize..size)
    static bool injectedOnce = false;
    if (g_licenseForceReset.exchange(false)) {
        injectedOnce = false;
        g_licenseDone = false;
    }
    if (injectedOnce) {
        g_licenseDone = true; // steady state — one-shot policy
        return true;
    }

    std::vector<uint32_t> appIds;
    AppManager::Get().GetUnlockedApps(appIds);

    auto& vec = pPkg->AppIdVec;
    const int64_t spareNow = static_cast<int64_t>(vec.m_Memory.m_nAllocationCount) - vec.m_Size;

    uint32_t missingTotal = 0;
    for (uint32_t id : appIds) {
        bool exists = false;
        for (uint32_t i = 0; i < vec.m_Size; ++i)
            if (vec.m_Memory.m_pMemory[i] == id) { exists = true; break; }
        if (!exists) ++missingTotal;
    }

    if (missingTotal == 0) {
        HookManager::Log("LicenseInjection: nothing to inject; entering steady state");
        injectedOnce = true;
        g_licenseDone = true;
        return true;
    }

    uint32_t written = AppendAppIds(pPkg, appIds);
    if (written < missingTotal && oCUtlMemoryGrow) {
        const int64_t needGrow = missingTotal - written - (spareNow > 0 ? spareNow : 0);
        if (needGrow > 0) {
            const uint32_t oldSize = vec.m_Size;
            const uint32_t oldAlloc = vec.m_Memory.m_nAllocationCount;
            if (GrowVectorRaw(&pPkg->AppIdVec, static_cast<int>(needGrow))) {
                const uint32_t newAlloc = vec.m_Memory.m_nAllocationCount;
                const uint32_t newSize = vec.m_Size;
                bool okA = (newAlloc >= oldSize + needGrow) && (newSize == oldSize);
                bool okB = (newSize == oldSize + needGrow) && (newAlloc >= newSize);
                if (okA || okB) {
                    HookManager::Log("LicenseInjection: grew vector " +
                                     std::to_string(oldAlloc) + "->" + std::to_string(newAlloc) +
                                     (okB ? " (size grew too)" : ""));
                    written += AppendAppIds(pPkg, appIds);
                } else {
                    HookManager::Log("LicenseInjection: grow postcondition unclear (" +
                                     std::to_string(oldAlloc) + "/" + std::to_string(newAlloc) +
                                     ", size " + std::to_string(oldSize) + "->" +
                                     std::to_string(newSize) + "); keeping capacity-only result");
                    // roll back any size change Valve's grow made so our append
                    // accounting stays consistent with what we wrote.
                    if (newSize != oldSize && newAlloc >= oldSize) {
                        vec.m_Size = oldSize;
                    }
                }
            } else {
                HookManager::Log("LicenseInjection: caught exception growing AppId vector");
            }
        }
    }

    if (written < missingTotal) {
        HookManager::Log("LicenseInjection: deferred " + std::to_string(missingTotal - written) +
                         " ids (capacity only)");
    } else {
        HookManager::Log("LicenseInjection: appended all " + std::to_string(written) +
                         " requested ids to package " + std::to_string(kInjectedPackageId));
    }
    injectedOnce = (written >= missingTotal); // retry allowed while capacity blocks us
    g_licenseDone = injectedOnce;

    if (written > 0) {
        // Mark the license changed so Steam's own background machinery notices.
        // ProcessPendingLicenseUpdates is experimental (ICEBREAKER_FULL=1): the
        // synchronous wait on unresolved appinfo throws when skip-flagging is
        // unavailable, and Steam processes the change asynchronously anyway.
        bool fullMode;
        {
            wchar_t flag[8] = {};
            fullMode = GetEnvironmentVariableW(L"ICEBREAKER_FULL", flag, 8) > 0 &&
                       (flag[0] == L'1' || flag[0] == L'y');
        }
        if (oMarkLicenseAsChanged && g_pCUser && MarkLicenseRaw(g_pCUser, kInjectedPackageId)) {
            HookManager::Log("MarkLicenseAsChanged: updated package " +
                             std::to_string(kInjectedPackageId));
        }
        if (fullMode && oProcessPendingLicenseUpdates && g_pCUser) {
            if (ProcessPendingRaw(g_pCUser)) {
                HookManager::Log("ProcessPendingLicenseUpdates: invoked");
            } else {
                HookManager::Log("ProcessPendingLicenseUpdates: exception swallowed");
            }
        }
    }
    return true;
}

static bool MaintenanceFence(void* pCPackageInfo, void* /*pCUser*/) {
    __try {
        return MaintenanceBody(pCPackageInfo);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

void PatchEngine::NotifyLicenseChanged(bool forceRescan) {
    // Safe from any thread: only raises the request; the actual mutation runs
    // inside Hook_CheckAppOwnership on Steam's own thread.
    if (forceRescan) {
        g_licenseForceReset.store(true);
        g_licenseDone = false;
        std::lock_guard<std::mutex> lock(g_virtualPkgMutex);
        g_virtualPackages.clear();
        g_virtualPkgAppStorage.clear();
    }
    // Re-arm so new apps in the Lua registry get appended to the package
    g_licenseDone = false;
    g_licenseChangeRequested.store(true);
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
    uint32_t ExistInPackageNums;
    char PurchaseCountryCode[4];
    uint32_t TimeStamp;
    uint32_t TimeExpire;
    bool bOwnsLicense;
    bool bLicenseExpired;
    bool bIsPermanent;
    bool bLowViolence;
    bool bFreeLicense;
    bool bRegionRestricted;
    bool bFromFreeWeekend;
    bool bLicenseLocked;
    bool bLicensePending;
    bool bRetailLicense;
    bool bAutoGrant;
    bool bLicensePermanent;
    bool bGuestPass;
    bool bBorrowed;
    bool bAnySiteLicense;
    bool bAllSiteLicenses;
    bool bAllActivationRequired;
    bool bFamilyShared;
};

typedef bool (*pfnCheckAppOwnership)(void* pThis, uint32_t appId, AppOwnership* pOwnership);
static pfnCheckAppOwnership oCheckAppOwnership = nullptr;

static bool Hook_CheckAppOwnership(void* pThis, uint32_t appId, AppOwnership* pOwn) {
    if (!g_pCUser) {
        g_pCUser = pThis;
        HookManager::Log("CheckAppOwnership: captured CUser");
    }

    bool result = oCheckAppOwnership ? oCheckAppOwnership(pThis, appId, pOwn) : false;

    // Single-owner rule: package mutation only happens here (Steam's thread,
    // after the original call has fully returned) when a change was requested.
    if (g_licenseChangeRequested.load(std::memory_order_acquire) || !g_licenseInitialized) {
        ConsumeLicenseMaintenance();
    }

    // Genuinely owned via real licenses (present in more than one actual package): leave Steam's
    // answer alone but keep the app marked Released so the library still lists it (OST parity).
    if (result && pOwn && pOwn->ExistInPackageNums > 1) {
        AppManager::Get().MarkOwned(appId);
        if (pOwn) pOwn->ReleaseState = 4; // AppReleaseState_Released
        return result;
    }

    if (AppManager::Get().IsAppUnlocked(appId) && !AppManager::Get().IsMarkedOwned(appId)) {
        if (pOwn) {
            uint32_t assignedPkg = AppManager::Get().GetAppPackageId(appId);
            pOwn->PackageId = (assignedPkg != 0) ? assignedPkg : kInjectedPackageId;
            pOwn->bOwnsLicense = true;
            pOwn->ReleaseState = 4; // AppReleaseState_Released
            pOwn->SteamId32 = PatchEngine::GetActiveAccountID();
            pOwn->bIsPermanent = true;
            pOwn->bLicensePermanent = true;
            pOwn->bFreeLicense = false;
            pOwn->bBorrowed = false;
            pOwn->bFamilyShared = false;
            pOwn->bGuestPass = false;
            pOwn->bLicenseLocked = false;
            pOwn->bLicensePending = false;
        }
        return true;
    }
    return result;
}

// ── steamclient64: GetPackageInfo hook for capturing CPackageInfo ─────
static PackageInfo* Hook_GetPackageInfo(void* pThis, uint32_t packageId, uint64_t accessToken) {
    if (!g_pCPackageInfo) {
        g_pCPackageInfo = pThis;
        HookManager::Log("GetPackageInfo: captured CPackageInfo");
    }

    // Check if this packageId is one of our virtual game packages
    {
        std::lock_guard<std::mutex> lock(g_virtualPkgMutex);
        auto it = g_virtualPackages.find(packageId);
        if (it != g_virtualPackages.end()) {
            return &it->second;
        }
    }

    PackageInfo* result = oGetPackageInfo ? oGetPackageInfo(pThis, packageId, accessToken) : nullptr;
    if (result) return result;

    // If Steam has no record of this packageId, check if it belongs to our unlocked games
    std::unordered_map<uint32_t, std::vector<uint32_t>> packages;
    AppManager::Get().GetPackages(packages);
    auto pkgIt = packages.find(packageId);
    if (pkgIt != packages.end()) {
        std::lock_guard<std::mutex> lock(g_virtualPkgMutex);
        auto& storage = g_virtualPkgAppStorage[packageId];
        storage = pkgIt->second;

        auto& pkg = g_virtualPackages[packageId];
        pkg.PackageId = packageId;
        pkg.ChangeNumber = 1;
        pkg.BillingType = 12; // FreeOnDemand / BillPrepurchase
        pkg.LicenseType = 1;  // SinglePurchase
        pkg.Status = 0;       // Available
        memset(pkg.SHA_1_Hash, 0, sizeof(pkg.SHA_1_Hash));
        pkg.pPackageInfoNodeBegin = nullptr;
        pkg.pExtendNodeBegin = nullptr;
        pkg.AppIdVec.m_Memory.m_pMemory = storage.data();
        pkg.AppIdVec.m_Memory.m_nAllocationCount = static_cast<int>(storage.size());
        pkg.AppIdVec.m_Size = static_cast<int>(storage.size());

        HookManager::Log("GetPackageInfo: synthesized virtual package " + std::to_string(packageId) +
                         " with " + std::to_string(storage.size()) + " appids");
        return &pkg;
    }

    return nullptr;
}

// ── steamclient64: ConfigStoreGetBinary hook for depot decryption keys ─
typedef int32_t (*pfnConfigStoreGetBinary_t)(void* pObject, int32_t eConfigStore, const char* KeyName, char* Key, uint32_t KeySize);
static pfnConfigStoreGetBinary_t oConfigStoreGetBinary = nullptr;

static int32_t Hook_ConfigStoreGetBinary(void* pObject, int32_t eConfigStore, const char* KeyName, char* Key, uint32_t KeySize) {
    if (KeyName) {
        std::string name(KeyName);
        // Normalize slashes
        for (char& c : name) {
            if (c == '/') c = '\\';
        }

        // Expected shape: "...\\<DepotId>\\DecryptionKey" or "<DepotId>\\DecryptionKey"
        size_t last = name.find("\\DecryptionKey");
        if (last == std::string::npos) {
            last = name.find("\\decryptionkey");
        }

        if (last != std::string::npos) {
            size_t start = name.find_last_of('\\', last - 1);
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

// ── steamclient64: CAppInfoCache::GetOrAddAppData skip-flag hook ──────
// Injected package ids (depot ids especially) can have only placeholder appinfo. That keeps
// CClientAppManager::ProcessPendingLicenseUpdates waiting on appinfo that will never arrive,
// which leaves the injected license half-applied and games fail to launch (Steam "Error 56").
// Marking such entries skip_flag makes Steam treat them like PICS unknown_appids instead
// (same fix OpenSteamTool applies in Hooks_Misc::GetOrAddAppData).
struct CAppData {
    void** vfptr;
    uint32_t nAppID;
    uint32_t ChangeNumber;
    uint32_t LastChangeTimeStamp;
    bool bSkipFlag;
    bool bDeniedToken;
    bool bMissingToken;
    uint64_t accessToken;
    uint8_t sha1Hash[20];

    bool HasEmptyAppInfoSha() const {
        static const uint8_t kEmptySha1[20] = {};
        return memcmp(sha1Hash, kEmptySha1, sizeof(sha1Hash)) == 0;
    }
};

typedef void* (*pfnGetOrAddAppData_t)(void* pCache, uint32_t appId, bool bCreate);
static pfnGetOrAddAppData_t oGetOrAddAppData = nullptr;

static void* Hook_GetOrAddAppData(void* pCache, uint32_t appId, bool bCreate) {
    void* result = oGetOrAddAppData ? oGetOrAddAppData(pCache, appId, bCreate) : nullptr;

    CAppData* app = static_cast<CAppData*>(result);
    if (app && !bCreate && AppManager::Get().IsAppUnlocked(appId) &&
        app->HasEmptyAppInfoSha() && !app->bSkipFlag) {
        app->bSkipFlag = true;
        HookManager::Log("GetOrAddAppData: flagged appId " + std::to_string(appId) +
                         " as skip (unresolved appinfo, unblocking license updates)");
    }
    return result;
}

// ── steamclient64: CConnectionTransport::BBuildAndAsyncSendFrame hook ─
// Outgoing CMsgClientPICSProductInfoRequest (eMsg 8903) patcher: injects the PICS access tokens
// configured via addtoken(id, "token") lua lines, so Steam resolves appinfo for token-protected
// injected apps. Packets without tokens are passed through untouched (zero overhead hot path).
struct MsgHdr {
    uint32_t eMsg;
    uint32_t headerLength;
};

constexpr uint32_t kMsgHdrProtoFlag = 0x80000000;
constexpr uint32_t kEMsgClientPICSProductInfoRequest = 8903;

static bool UnpackSendPacket(const uint8_t* data, uint32_t size,
                             uint32_t& eMsg, const uint8_t*& pHdr, uint32_t& cbHdr,
                             const uint8_t*& pBody, uint32_t& cbBody) {
    if (!data || size < sizeof(MsgHdr)) return false;
    const MsgHdr* hdr = reinterpret_cast<const MsgHdr*>(data);
    if (!(hdr->eMsg & kMsgHdrProtoFlag)) return false;
    eMsg = hdr->eMsg & ~kMsgHdrProtoFlag;
    cbHdr = hdr->headerLength;
    uint32_t off = sizeof(MsgHdr) + cbHdr;
    if (off > size) return false;
    pHdr = data + sizeof(MsgHdr);
    pBody = data + off;
    cbBody = size - off;
    return true;
}

static uint64_t ReadVarint(const uint8_t*& p, const uint8_t* end, bool& ok) {
    uint64_t value = 0;
    int shift = 0;
    ok = false;
    while (p < end && shift < 64) {
        uint8_t b = *p++;
        value |= static_cast<uint64_t>(b & 0x7F) << shift;
        if (!(b & 0x80)) { ok = true; break; }
        shift += 7;
    }
    return value;
}

static void WriteVarint(std::vector<uint8_t>& out, uint64_t value) {
    while (true) {
        uint8_t b = static_cast<uint8_t>(value & 0x7F);
        value >>= 7;
        if (value) out.push_back(b | 0x80);
        else { out.push_back(b); break; }
    }
}

// One parsed protobuf field kept as raw bytes so untouched fields round-trip byte-identical.
struct ProtoField {
    uint32_t fieldNumber;
    uint8_t wireType;
    std::vector<uint8_t> raw; // tag + payload
};

static bool ParseProtoFields(const uint8_t* p, const uint8_t* end, std::vector<ProtoField>& out) {
    while (p < end) {
        bool ok = false;
        uint64_t key = ReadVarint(p, end, ok);
        if (!ok) return false;
        ProtoField f;
        f.wireType = static_cast<uint8_t>(key & 7);
        f.fieldNumber = static_cast<uint32_t>(key >> 3);
        f.raw.push_back(static_cast<uint8_t>(key & 0xFF));
        // Re-encode the full tag varint (multi-byte tags are rare; handle via WriteVarint).
        f.raw.clear();
        WriteVarint(f.raw, key);
        switch (f.wireType) {
            case 0: { // varint
                uint64_t v = ReadVarint(p, end, ok);
                if (!ok) return false;
                WriteVarint(f.raw, v);
                break;
            }
            case 1: { // fixed64
                if (end - p < 8) return false;
                f.raw.insert(f.raw.end(), p, p + 8); p += 8;
                break;
            }
            case 2: { // length-delimited
                uint64_t len = ReadVarint(p, end, ok);
                if (!ok || end - p < len) return false;
                WriteVarint(f.raw, len);
                f.raw.insert(f.raw.end(), p, p + len); p += len;
                break;
            }
            case 5: { // fixed32
                if (end - p < 4) return false;
                f.raw.insert(f.raw.end(), p, p + 4); p += 4;
                break;
            }
            default: return false; // groups (3,4) are deprecated and never used here
        }
        out.push_back(std::move(f));
    }
    return true;
}

// Rebuild one apps submessage with the access token forced to the configured value. Returns false
// when the submessage is malformed or needs no change.
static bool PatchAppSubmessage(const std::vector<ProtoField>& fields, std::vector<ProtoField>& out) {
    uint64_t appId = 0, currentToken = 0;
    bool hasAppId = false, hasToken = false;
    for (const auto& f : fields) {
        if (f.fieldNumber == 1 && f.wireType == 0) {
            // decode varint from raw payload
            const uint8_t* q = f.raw.data() + 1;
            const uint8_t* qEnd = f.raw.data() + f.raw.size();
            bool ok = false;
            appId = ReadVarint(q, qEnd, ok);
            hasAppId = ok;
        } else if (f.fieldNumber == 2 && f.wireType == 0) {
            const uint8_t* q = f.raw.data() + 1;
            const uint8_t* qEnd = f.raw.data() + f.raw.size();
            bool ok = false;
            currentToken = ReadVarint(q, qEnd, ok);
            hasToken = ok;
        }
    }
    if (!hasAppId) return false;

    uint64_t wanted = 0;
    if (!AppManager::Get().GetAccessToken(static_cast<uint32_t>(appId), wanted)) return false;
    if (hasToken && currentToken == wanted) return false;

    out.clear();
    bool tokenWritten = false;
    for (const auto& f : fields) {
        if (f.fieldNumber == 2 && f.wireType == 0) {
            if (!tokenWritten) {
                ProtoField tok;
                tok.fieldNumber = 2; tok.wireType = 0;
                WriteVarint(tok.raw, (2ULL << 3) | 0);
                WriteVarint(tok.raw, wanted);
                out.push_back(std::move(tok));
                tokenWritten = true;
            }
            continue; // drop the original token field
        }
        out.push_back(f);
    }
    if (!tokenWritten) {
        ProtoField tok;
        tok.fieldNumber = 2; tok.wireType = 0;
        WriteVarint(tok.raw, (2ULL << 3) | 0);
        WriteVarint(tok.raw, wanted);
        out.push_back(std::move(tok));
    }
    return true;
}

static bool (*oBBuildAndAsyncSendFrame)(void*, uint32_t, uint8_t*, uint32_t) = nullptr;
static uint8_t g_sendPatchBuffer[256 * 1024];

static bool Hook_BBuildAndAsyncSendFrame(void* pObject, uint32_t opCode, uint8_t* pubData, uint32_t cubData) {
    uint32_t eMsg = 0;
    const uint8_t* pHdr = nullptr;
    uint32_t cbHdr = 0;
    const uint8_t* pBody = nullptr;
    uint32_t cbBody = 0;

    if (pubData && cubData >= sizeof(MsgHdr) &&
        UnpackSendPacket(pubData, cubData, eMsg, pHdr, cbHdr, pBody, cbBody) &&
        eMsg == kEMsgClientPICSProductInfoRequest &&
        AppManager::Get().HasAnyAccessToken()) {
        std::vector<ProtoField> top;
        if (ParseProtoFields(pBody, pBody + cbBody, top)) {
            bool changed = false;
            std::vector<std::vector<uint8_t>> rebuilt(top.size());
            for (size_t i = 0; i < top.size(); ++i) {
                if (top[i].fieldNumber == 1 && top[i].wireType == 2) {
                    // strip tag+len (already re-encoded in raw) → payload
                    const uint8_t* q = top[i].raw.data() + 1;
                    const uint8_t* qEnd = top[i].raw.data() + top[i].raw.size();
                    bool ok = false;
                    uint64_t len = ReadVarint(q, qEnd, ok);
                    if (ok) {
                        std::vector<ProtoField> inner;
                        if (ParseProtoFields(q, q + len, inner)) {
                            std::vector<ProtoField> patched;
                            if (PatchAppSubmessage(inner, patched)) {
                                // re-encode submessage payload
                                std::vector<uint8_t> payload;
                                for (const auto& f : patched) payload.insert(payload.end(), f.raw.begin(), f.raw.end());
                                std::vector<uint8_t> nraw;
                                WriteVarint(nraw, (1ULL << 3) | 2);
                                WriteVarint(nraw, payload.size());
                                nraw.insert(nraw.end(), payload.begin(), payload.end());
                                rebuilt[i] = std::move(nraw);
                                changed = true;
                                continue;
                            }
                        }
                    }
                }
            }

            if (changed) {
                std::vector<uint8_t> body;
                for (size_t i = 0; i < top.size(); ++i) {
                    const std::vector<uint8_t>& raw = rebuilt[i].empty() ? top[i].raw : rebuilt[i];
                    body.insert(body.end(), raw.begin(), raw.end());
                }

                uint32_t newSize = sizeof(MsgHdr) + cbHdr + static_cast<uint32_t>(body.size());
                if (newSize <= sizeof(g_sendPatchBuffer)) {
                    uint8_t* out = g_sendPatchBuffer;
                    memcpy(out, pubData, sizeof(MsgHdr) + cbHdr);
                    memcpy(out + sizeof(MsgHdr) + cbHdr, body.data(), body.size());
                    HookManager::Log("PICS: injected access tokens into CMsgClientPICSProductInfoRequest (" +
                                     std::to_string(cbBody) + " -> " + std::to_string(body.size()) + " bytes)");
                    return oBBuildAndAsyncSendFrame
                        ? oBBuildAndAsyncSendFrame(pObject, opCode, out, newSize)
                        : false;
                }
            }
        }
    }

    return oBBuildAndAsyncSendFrame
        ? oBBuildAndAsyncSendFrame(pObject, opCode, pubData, cubData)
        : false;
}

// ── steamui.dll: library visibility hook ──────────────────────────────
typedef bool (*pfnShouldShowAppInLibrary)(void* pThis, uint32_t appId);
static pfnShouldShowAppInLibrary oShouldShowAppInLibrary = nullptr;

static bool Hook_ShouldShowAppInLibrary(void* pThis, uint32_t appId) {
    if (AppManager::Get().IsAppUnlocked(appId)) {
        return true;
    }
    // Delegate all non-Lua apps to Steam's native ownership check so owned games are never hidden.
    return oShouldShowAppInLibrary ? oShouldShowAppInLibrary(pThis, appId) : false;
}

// Names whose address gets DETOURed. For these the match must be unique across
// the executable sections — a generic-prologue multi-match silently hooks an
// unrelated function (the corruption class behind past "Loading user data"
// crashes). Resolver-only names (function pointers we merely call) may keep
// first-match semantics.
static bool IsHookedName(const char* name) {
    static const char* kHooked[] = {
        "ShouldShowAppInLibrary", "CheckAppOwnership", "GetPackageInfo",
        "ConfigStoreGetBinary",   "GetOrAddAppData",   "BBuildAndAsyncSendFrame",
    };
    for (const char* n : kHooked)
        if (strcmp(n, name) == 0) return true;
    return false;
}

// ── resolution bookkeeping ────────────────────────────────────────────
static void Resolve(const PatternDefinition& pat, uintptr_t base, const char* tag,
                    const std::unordered_map<std::string, std::vector<std::string>>& otaPatterns) {
    if (PatchEngine::ResolvedAddress(pat.name)) return;

    HMODULE hMod = reinterpret_cast<HMODULE>(base);

    // 0. Fast-path: Check PE Timestamp & Size RVA Cache (0 ms, 0 pattern scanning)
    if (uintptr_t cachedAddr = RvaCache::GetCachedAddress(hMod, pat.name)) {
        PatchEngine::CacheResolved(pat.name, cachedAddr);
        HookManager::Log(std::string(tag) + ": found " + pat.name + " via RVA Cache at " + Hex(cachedAddr));
        return;
    }

    // 1. Try local patterns first
    for (const auto& sig : pat.patterns) {
        uintptr_t addr = Scanner::ScanModule(hMod, sig);
        if (addr) {
            if (IsHookedName(pat.name)) {
                size_t hits = Scanner::CountMatches(hMod, sig);
                if (hits != 1) {
                    HookManager::Log(std::string(tag) + ": " + pat.name +
                                     " matched " + std::to_string(hits) +
                                     " locations — ambiguous, hook skipped (non-fatal)");
                    return;
                }
            }
            PatchEngine::CacheResolved(pat.name, addr);
            RvaCache::SaveAddress(hMod, pat.name, addr);
            HookManager::Log(std::string(tag) + ": found " + pat.name + " at " + Hex(addr));
            return;
        }
    }

    // 2. Fallback to OTA patterns if available
    auto it = otaPatterns.find(pat.name);
    if (it != otaPatterns.end()) {
        for (const auto& otaSig : it->second) {
            uintptr_t addr = Scanner::ScanModule(hMod, otaSig);
            if (addr) {
                PatchEngine::CacheResolved(pat.name, addr);
                RvaCache::SaveAddress(hMod, pat.name, addr);
                HookManager::Log(std::string(tag) + ": found " + pat.name + " via OTA at " + Hex(addr));
                return;
            }
        }
    }

    // 3. Fallback to in-engine heuristic discovery (string / constant xref & prologue back-scan)
    uintptr_t heuristicAddr = 0;
    if (strcmp(pat.name, "ConfigStoreGetBinary") == 0) {
        if (uintptr_t xref = HeuristicResolver::FindXref(hMod, "ConfigStore")) {
            heuristicAddr = HeuristicResolver::FindPrologue(xref);
        }
    } else if (strcmp(pat.name, "ShouldShowAppInLibrary") == 0) {
        // Look for 0x090CD6 constant
        if (uintptr_t xref = HeuristicResolver::FindConst32(hMod, 0x090CD6)) {
            heuristicAddr = HeuristicResolver::FindPrologue(xref);
        }
    } else if (strcmp(pat.name, "GetOrAddAppData") == 0) {
        if (uintptr_t xref = HeuristicResolver::FindXref(hMod, "AppInfo")) {
            heuristicAddr = HeuristicResolver::FindPrologue(xref);
        }
    } else if (strcmp(pat.name, "BBuildAndAsyncSendFrame") == 0) {
        if (uintptr_t xref = HeuristicResolver::FindXref(hMod, "WebSocket")) {
            heuristicAddr = HeuristicResolver::FindPrologue(xref);
        }
    } else if (strcmp(pat.name, "CheckAppOwnership") == 0) {
        if (uintptr_t xref = HeuristicResolver::FindXref(hMod, "CheckAppOwnership")) {
            heuristicAddr = HeuristicResolver::FindPrologue(xref);
        }
    } else if (strcmp(pat.name, "GetPackageInfo") == 0) {
        if (uintptr_t xref = HeuristicResolver::FindXref(hMod, "Package")) {
            heuristicAddr = HeuristicResolver::FindPrologue(xref);
        }
    }

    if (heuristicAddr) {
        PatchEngine::CacheResolved(pat.name, heuristicAddr);
        RvaCache::SaveAddress(hMod, pat.name, heuristicAddr);
        HookManager::Log(std::string(tag) + ": recovered " + pat.name + " via Heuristic at " + Hex(heuristicAddr));

        // Auto-synthesize pattern and store in local cache so future boots load instantly
        std::string synthPat = HeuristicResolver::SynthesizePattern(heuristicAddr);
        if (!synthPat.empty()) {
            OtaClient::CacheSynthesizedPattern(pat.name, synthPat);
        }
        return;
    }

    HookManager::Log(std::string(tag) + ": pattern not matched: " + pat.name + " (non-fatal)");
}

void PatchEngine::ApplyInMemoryPatches() {
    try {
        const uintptr_t ui = UIBase();
        const uintptr_t client = ClientBase();

        if (!ui && !client) {
            HookManager::Log("ApplyInMemoryPatches: neither steamui nor steamclient64 loaded; skipping.");
            return;
        }

        HookManager::Log("Scanning in-memory patterns (steamui=" + Hex(ui) + " steamclient64=" + Hex(client) + ")");

        // Query OTA pattern feed asynchronously or on startup with local cache fallback
        auto otaPatterns = OtaClient::FetchPatterns();
        if (!otaPatterns.empty()) {
            HookManager::Log("OTA: Loaded " + std::to_string(otaPatterns.size()) + " pattern definitions from OTA/cache.");
        }

        if (ui) {
            for (const auto& pat : g_SteamUIPatterns) {
                try {
                    Resolve(pat, ui, "steamui", otaPatterns);
                } catch (...) {
                    HookManager::Log("ApplyInMemoryPatches: exception resolving steamui pattern " + std::string(pat.name));
                }
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
                try {
                    Resolve(pat, client, "steamclient64", otaPatterns);
                } catch (...) {
                    HookManager::Log("ApplyInMemoryPatches: exception resolving steamclient64 pattern " + std::string(pat.name));
                }
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
            if (auto addr = ResolvedAddress("GetOrAddAppData")) {
                // OPT-IN ONLY: the current signature is ambiguous (generic prologue),
                // so an unknown function could be hooked and its return misused as a
                // CAppInfoCache entry — one of the corruption sources behind the
                // "Loading user data" crashes. Enable with ICEBREAKER_APPDATA_HOOK=1
                // only while actively debugging the anchor.
                wchar_t flag[8] = {};
                bool enabled = GetEnvironmentVariableW(L"ICEBREAKER_APPDATA_HOOK", flag, 8) > 0 &&
                               (flag[0] == L'1' || flag[0] == L'y');
                if (!enabled) {
                    HookManager::Log("GetOrAddAppData: resolved but hook disabled by default (ambiguous signature; set ICEBREAKER_APPDATA_HOOK=1 to enable)");
                } else {
                    HookManager::CreateHook(reinterpret_cast<void*>(addr),
                                            reinterpret_cast<void*>(&Hook_GetOrAddAppData),
                                            reinterpret_cast<void**>(&oGetOrAddAppData),
                                            "GetOrAddAppData");
                }
            }
            if (auto addr = ResolvedAddress("BBuildAndAsyncSendFrame")) {
                // OPT-IN while stabilizing: the PICS access-token patcher re-encodes
                // live IPC transport packets during login; its frame layout for this
                // build is not independently verified yet. Enable the token rewrite
                // with ICEBREAKER_FULL=1 only after a clean safe-mode boot.
                wchar_t flag[8] = {};
                bool enabled = GetEnvironmentVariableW(L"ICEBREAKER_FULL", flag, 8) > 0 &&
                               (flag[0] == L'1' || flag[0] == L'y');
                if (!enabled) {
                    HookManager::Log("BBuildAndAsyncSendFrame: resolved but PICS rewrite disabled by default (set ICEBREAKER_FULL=1 to enable)");
                } else {
                    HookManager::CreateHook(reinterpret_cast<void*>(addr),
                                            reinterpret_cast<void*>(&Hook_BBuildAndAsyncSendFrame),
                                            reinterpret_cast<void**>(&oBBuildAndAsyncSendFrame),
                                            "BBuildAndAsyncSendFrame");
                }
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
    } catch (const std::exception& ex) {
        HookManager::Log("ApplyInMemoryPatches: fatal exception caught: " + std::string(ex.what()) + "; Steam kept running safely.");
    } catch (...) {
        HookManager::Log("ApplyInMemoryPatches: unknown exception caught; Steam kept running safely.");
    }
}

} // namespace IceBreaker
