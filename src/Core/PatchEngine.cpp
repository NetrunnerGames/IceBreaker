#include "PatchEngine.h"
#include "Scanner.h"
#include "Patterns.h"
#include "OtaClient.h"
#include "HeuristicResolver.h"
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
        if (g_licenseRefreshPending) {
            MarkLicenseAsChangedAndProcessUpdates();
            g_licenseRefreshPending = false;
        }
    }

    bool result = oCheckAppOwnership ? oCheckAppOwnership(pThis, appId, pOwn) : false;
    TryInitFakeLicenseOnce();

    // Genuinely owned via real licenses (present in more than one actual package): leave Steam's
    // answer alone and remember it, so we never spoof on top of real ownership (OST parity).
    if (result && pOwn && pOwn->ExistInPackageNums > 1) {
        AppManager::Get().MarkOwned(appId);
        return result;
    }

    if (AppManager::Get().IsAppUnlocked(appId) && !AppManager::Get().IsMarkedOwned(appId)) {
        if (pOwn) {
            pOwn->PackageId = kInjectedPackageId;
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
    if (oShouldShowAppInLibrary) {
        return oShouldShowAppInLibrary(pThis, appId);
    }
    return true;
}

// ── resolution bookkeeping ────────────────────────────────────────────
static void Resolve(const PatternDefinition& pat, uintptr_t base, const char* tag,
                    const std::unordered_map<std::string, std::vector<std::string>>& otaPatterns) {
    if (PatchEngine::ResolvedAddress(pat.name)) return;

    // 1. Try local patterns first
    for (const auto& sig : pat.patterns) {
        uintptr_t addr = Scanner::ScanModule(reinterpret_cast<HMODULE>(base), sig);
        if (addr) {
            PatchEngine::CacheResolved(pat.name, addr);
            HookManager::Log(std::string(tag) + ": found " + pat.name + " at " + Hex(addr));
            return;
        }
    }

    // 2. Fallback to OTA patterns if available
    auto it = otaPatterns.find(pat.name);
    if (it != otaPatterns.end()) {
        for (const auto& otaSig : it->second) {
            uintptr_t addr = Scanner::ScanModule(reinterpret_cast<HMODULE>(base), otaSig);
            if (addr) {
                PatchEngine::CacheResolved(pat.name, addr);
                HookManager::Log(std::string(tag) + ": found " + pat.name + " via OTA at " + Hex(addr));
                return;
            }
        }
    }

    // 3. Fallback to in-engine heuristic discovery (string / constant xref & prologue back-scan)
    if (strcmp(pat.name, "ConfigStoreGetBinary") == 0) {
        if (uintptr_t xref = HeuristicResolver::FindXref(reinterpret_cast<HMODULE>(base), "ConfigStore")) {
            if (uintptr_t prologue = HeuristicResolver::FindPrologue(xref)) {
                PatchEngine::CacheResolved(pat.name, prologue);
                HookManager::Log(std::string(tag) + ": recovered " + pat.name + " via Heuristic at " + Hex(prologue));
                return;
            }
        }
    }

    HookManager::Log(std::string(tag) + ": pattern not matched: " + pat.name + " (non-fatal)");
}

void PatchEngine::ApplyInMemoryPatches() {
    const uintptr_t ui = UIBase();
    const uintptr_t client = ClientBase();
    HookManager::Log("Scanning in-memory patterns (steamui=" + Hex(ui) + " steamclient64=" + Hex(client) + ")");

    // Query OTA pattern feed asynchronously or on startup with local cache fallback
    auto otaPatterns = OtaClient::FetchPatterns();
    if (!otaPatterns.empty()) {
        HookManager::Log("OTA: Loaded " + std::to_string(otaPatterns.size()) + " pattern definitions from OTA/cache.");
    }

    if (ui) {
        for (const auto& pat : g_SteamUIPatterns) {
            Resolve(pat, ui, "steamui", otaPatterns);
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
            Resolve(pat, client, "steamclient64", otaPatterns);
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
            HookManager::CreateHook(reinterpret_cast<void*>(addr),
                                    reinterpret_cast<void*>(&Hook_GetOrAddAppData),
                                    reinterpret_cast<void**>(&oGetOrAddAppData),
                                    "GetOrAddAppData");
        }
        if (auto addr = ResolvedAddress("BBuildAndAsyncSendFrame")) {
            HookManager::CreateHook(reinterpret_cast<void*>(addr),
                                    reinterpret_cast<void*>(&Hook_BBuildAndAsyncSendFrame),
                                    reinterpret_cast<void**>(&oBBuildAndAsyncSendFrame),
                                    "BBuildAndAsyncSendFrame");
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
