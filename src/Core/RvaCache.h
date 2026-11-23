#pragma once
#include <windows.h>
#include <wininet.h>
#include <string>
#include <unordered_map>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <shlwapi.h>
#include <thread>
#include "HookManager.h"

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "shlwapi.lib")

namespace IceBreaker {

/// <summary>
/// Manages $O(1)$ fast-path RVA resolution based on the module's unique PE header signature
/// (TimeDateStamp + SizeOfImage). Integrates with Cloudflare KV edge cache:
/// 1. Local disk cache lookup (0 ms)
/// 2. Remote Cloudflare KV query if local cache misses (<15 ms)
/// 3. Async background submission to Cloudflare KV when local heuristic recovers a new build
/// </summary>
class RvaCache {
public:
    static constexpr const char* KV_API_BASE = "https://bots.netrunnergames.workers.dev/api/rva";
    static constexpr const char* IB_SECRET = "ib_netrunner_sec_99a8b7";

    static std::string GetModuleBuildId(HMODULE hMod) {
        if (!hMod) return "";
        auto dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(hMod);
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return "";

        auto ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(reinterpret_cast<const uint8_t*>(hMod) + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return "";

        uint32_t timeStamp = ntHeaders->FileHeader.TimeDateStamp;
        uint32_t sizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;

        std::ostringstream ss;
        ss << std::hex << std::uppercase << std::setfill('0')
           << std::setw(8) << timeStamp << "-"
           << std::setw(8) << sizeOfImage;
        return ss.str();
    }

    static uintptr_t GetCachedAddress(HMODULE hMod, const std::string& funcName) {
        if (!hMod) return 0;
        std::string buildId = GetModuleBuildId(hMod);
        if (buildId.empty()) return 0;

        std::wstring cachePath = GetRvaCachePath();
        std::string content = LoadFile(cachePath);

        // 1. Check local file cache
        if (!content.empty()) {
            uintptr_t rva = QueryRvaFromJson(content, buildId, funcName);
            if (rva) {
                return reinterpret_cast<uintptr_t>(hMod) + rva;
            }
        }

        // 2. Local miss: Query Cloudflare KV edge for this build
        static std::string s_lastCheckedBuild;
        if (s_lastCheckedBuild != buildId) {
            s_lastCheckedBuild = buildId;
            std::string kvData = FetchFromKV(buildId);
            if (!kvData.empty()) {
                // Merge into local cache
                MergeIntoLocalCache(buildId, kvData);
                content = LoadFile(cachePath);
                uintptr_t rva = QueryRvaFromJson(content, buildId, funcName);
                if (rva) {
                    HookManager::Log("RvaCache: Resolved " + funcName + " via Cloudflare KV for build " + buildId);
                    return reinterpret_cast<uintptr_t>(hMod) + rva;
                }
            }
        }

        return 0;
    }

    static void SaveAddress(HMODULE hMod, const std::string& funcName, uintptr_t funcAddress) {
        if (!hMod || !funcAddress) return;
        std::string buildId = GetModuleBuildId(hMod);
        if (buildId.empty()) return;

        uintptr_t base = reinterpret_cast<uintptr_t>(hMod);
        if (funcAddress < base) return;
        uintptr_t rva = funcAddress - base;

        std::wstring cachePath = GetRvaCachePath();
        std::string content = LoadFile(cachePath);
        auto data = ParseRvaJson(content);

        data[buildId][funcName] = rva;

        // Serialize
        std::ostringstream ss;
        ss << "{\n";
        size_t bCount = 0;
        for (const auto& [bId, funcs] : data) {
            ss << "  \"" << bId << "\": {\n";
            size_t fCount = 0;
            for (const auto& [fName, fRva] : funcs) {
                ss << "    \"" << fName << "\": \"0x" << std::hex << fRva << "\""
                   << (fCount + 1 < funcs.size() ? "," : "") << "\n";
                fCount++;
            }
            ss << "  }" << (bCount + 1 < data.size() ? "," : "") << "\n";
            bCount++;
        }
        ss << "}\n";

        SaveFile(cachePath, ss.str());
        HookManager::Log("RvaCache: Saved " + funcName + " (RVA 0x" + Hex(rva) + ") for build " + buildId);

        // Submit to Cloudflare KV asynchronously in background thread so user flow never blocks
        SubmitToKVAsync(buildId, funcName, rva);
    }

private:
    static std::string Hex(uintptr_t val) {
        std::ostringstream ss;
        ss << std::hex << val;
        return ss.str();
    }

    static std::wstring GetRvaCachePath() {
        wchar_t steamPath[MAX_PATH] = { 0 };
        DWORD pathSize = sizeof(steamPath);
        if (RegGetValueW(HKEY_CURRENT_USER, L"Software\\Valve\\Steam", L"SteamPath",
                         RRF_RT_REG_SZ, nullptr, steamPath, &pathSize) == ERROR_SUCCESS) {
            return std::wstring(steamPath) + L"\\config\\icebreaker_rva_cache.json";
        }
        wchar_t currentDir[MAX_PATH] = { 0 };
        GetModuleFileNameW(nullptr, currentDir, MAX_PATH);
        PathRemoveFileSpecW(currentDir);
        return std::wstring(currentDir) + L"\\config\\icebreaker_rva_cache.json";
    }

    static std::string LoadFile(const std::wstring& path) {
        HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                   nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) return "";

        DWORD size = GetFileSize(hFile, nullptr);
        if (size == 0 || size > 2 * 1024 * 1024) {
            CloseHandle(hFile);
            return "";
        }
        std::string buf(size, '\0');
        DWORD read = 0;
        ReadFile(hFile, &buf[0], size, &read, nullptr);
        CloseHandle(hFile);
        return buf;
    }

    static void SaveFile(const std::wstring& path, const std::string& content) {
        HANDLE hFile = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
                                   CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile != INVALID_HANDLE_VALUE) {
            DWORD written = 0;
            WriteFile(hFile, content.data(), static_cast<DWORD>(content.size()), &written, nullptr);
            CloseHandle(hFile);
        }
    }

    static std::string FetchFromKV(const std::string& buildId) {
        std::string url = std::string(KV_API_BASE) + "?build=" + buildId;
        HINTERNET hInternet = InternetOpenA("IceBreaker-KV/1.0", INTERNET_OPEN_TYPE_PRECONFIG, nullptr, nullptr, 0);
        if (!hInternet) return "";

        DWORD flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_SECURE;
        HINTERNET hUrl = InternetOpenUrlA(hInternet, url.c_str(), nullptr, 0, flags, 0);
        if (!hUrl) {
            InternetCloseHandle(hInternet);
            return "";
        }

        std::string response;
        char buffer[2048];
        DWORD bytesRead = 0;
        while (InternetReadFile(hUrl, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
            response.append(buffer, bytesRead);
        }

        InternetCloseHandle(hUrl);
        InternetCloseHandle(hInternet);
        return response;
    }

    static void MergeIntoLocalCache(const std::string& buildId, const std::string& kvJson) {
        std::wstring cachePath = GetRvaCachePath();
        std::string localContent = LoadFile(cachePath);
        auto data = ParseRvaJson(localContent);

        // Parse key-value from KV format {"CheckAppOwnership": "0xa03a70", ...}
        size_t pos = 0;
        while (pos < kvJson.size()) {
            size_t kStart = kvJson.find('"', pos);
            if (kStart == std::string::npos) break;
            size_t kEnd = kvJson.find('"', kStart + 1);
            if (kEnd == std::string::npos) break;
            std::string key = kvJson.substr(kStart + 1, kEnd - kStart - 1);

            size_t vStart = kvJson.find('"', kEnd + 1);
            if (vStart == std::string::npos) break;
            size_t vEnd = kvJson.find('"', vStart + 1);
            if (vEnd == std::string::npos) break;
            std::string val = kvJson.substr(vStart + 1, vEnd - vStart - 1);

            try {
                data[buildId][key] = std::stoull(val, nullptr, 16);
            } catch (...) {}
            pos = vEnd + 1;
        }

        // Save merged
        std::ostringstream ss;
        ss << "{\n";
        size_t bCount = 0;
        for (const auto& [bId, funcs] : data) {
            ss << "  \"" << bId << "\": {\n";
            size_t fCount = 0;
            for (const auto& [fName, fRva] : funcs) {
                ss << "    \"" << fName << "\": \"0x" << std::hex << fRva << "\""
                   << (fCount + 1 < funcs.size() ? "," : "") << "\n";
                fCount++;
            }
            ss << "  }" << (bCount + 1 < data.size() ? "," : "") << "\n";
            bCount++;
        }
        ss << "}\n";
        SaveFile(cachePath, ss.str());
    }

    static void SubmitToKVAsync(const std::string& buildId, const std::string& funcName, uintptr_t rva) {
        std::thread([buildId, funcName, rva]() {
            HINTERNET hInternet = InternetOpenA("IceBreaker-KV/1.0", INTERNET_OPEN_TYPE_PRECONFIG, nullptr, nullptr, 0);
            if (!hInternet) return;

            HINTERNET hConnect = InternetConnectA(hInternet, "bots.netrunnergames.workers.dev",
                                                  INTERNET_DEFAULT_HTTPS_PORT, nullptr, nullptr,
                                                  INTERNET_SERVICE_HTTP, 0, 0);
            if (!hConnect) {
                InternetCloseHandle(hInternet);
                return;
            }

            HINTERNET hRequest = HttpOpenRequestA(hConnect, "POST", "/api/rva", nullptr, nullptr,
                                                 nullptr, INTERNET_FLAG_SECURE | INTERNET_FLAG_RELOAD, 0);
            if (hRequest) {
                std::string headers = "Content-Type: application/json\r\nX-IceBreaker-Token: " + std::string(IB_SECRET) + "\r\n";
                std::ostringstream body;
                body << "{\"buildId\":\"" << buildId << "\",\"rvas\":{\"" << funcName << "\":\"0x" << std::hex << rva << "\"}}";
                std::string bodyStr = body.str();

                HttpSendRequestA(hRequest, headers.c_str(), static_cast<DWORD>(headers.length()),
                                 const_cast<char*>(bodyStr.c_str()), static_cast<DWORD>(bodyStr.length()));
                InternetCloseHandle(hRequest);
            }
            InternetCloseHandle(hConnect);
            InternetCloseHandle(hInternet);
        }).detach();
    }

    static std::unordered_map<std::string, std::unordered_map<std::string, uintptr_t>> ParseRvaJson(const std::string& json) {
        std::unordered_map<std::string, std::unordered_map<std::string, uintptr_t>> result;
        if (json.empty()) return result;

        size_t pos = 0;
        while (pos < json.size()) {
            size_t buildStart = json.find('"', pos);
            if (buildStart == std::string::npos) break;
            size_t buildEnd = json.find('"', buildStart + 1);
            if (buildEnd == std::string::npos) break;

            std::string buildId = json.substr(buildStart + 1, buildEnd - buildStart - 1);
            pos = buildEnd + 1;

            size_t openBrace = json.find('{', pos);
            if (openBrace == std::string::npos) break;
            size_t closeBrace = json.find('}', openBrace + 1);
            if (closeBrace == std::string::npos) break;

            std::string block = json.substr(openBrace + 1, closeBrace - openBrace - 1);
            pos = closeBrace + 1;

            size_t bPos = 0;
            while (bPos < block.size()) {
                size_t fnStart = block.find('"', bPos);
                if (fnStart == std::string::npos) break;
                size_t fnEnd = block.find('"', fnStart + 1);
                if (fnEnd == std::string::npos) break;
                std::string fnName = block.substr(fnStart + 1, fnEnd - fnStart - 1);

                size_t valStart = block.find('"', fnEnd + 1);
                if (valStart == std::string::npos) break;
                size_t valEnd = block.find('"', valStart + 1);
                if (valEnd == std::string::npos) break;
                std::string valStr = block.substr(valStart + 1, valEnd - valStart - 1);

                uintptr_t rva = 0;
                try {
                    rva = std::stoull(valStr, nullptr, 16);
                } catch (...) {}

                if (rva) result[buildId][fnName] = rva;
                bPos = valEnd + 1;
            }
        }
        return result;
    }

    static uintptr_t QueryRvaFromJson(const std::string& json, const std::string& buildId, const std::string& funcName) {
        auto map = ParseRvaJson(json);
        auto bIt = map.find(buildId);
        if (bIt != map.end()) {
            auto fIt = bIt->second.find(funcName);
            if (fIt != bIt->second.end()) {
                return fIt->second;
            }
        }
        return 0;
    }
};

} // namespace IceBreaker
