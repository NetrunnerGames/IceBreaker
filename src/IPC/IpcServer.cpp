#include "IpcServer.h"
#include "../Core/HookManager.h"
#include "../Core/PatchEngine.h"
#include "../Steam/AppManager.h"
#include "../Steam/LuaLoader.h"
#include <windows.h>
#include <thread>
#include <atomic>
#include <vector>
#include <sstream>

namespace IceBreaker {

static const wchar_t* kPipeName = L"\\\\.\\pipe\\IceBreaker_IPC";
static std::atomic<bool> s_running{ false };
static std::thread s_worker;
static HANDLE s_pipeHandle = INVALID_HANDLE_VALUE;

std::string IpcServer::ProcessCommand(const std::string& raw) {
    // 1. Length validation to prevent buffer/string abuse
    if (raw.empty()) {
        return "ERROR: empty command\n";
    }
    if (raw.length() > 512) {
        return "ERROR: command exceeds maximum length\n";
    }

    // 2. Character validation: permit only printable ASCII and whitespace
    for (unsigned char c : raw) {
        if (c < 32 && c != '\r' && c != '\n' && c != '\t') {
            return "ERROR: invalid characters in command\n";
        }
    }

    // Trim whitespace and newlines
    std::string cmd = raw;
    while (!cmd.empty() && (cmd.back() == '\r' || cmd.back() == '\n' || cmd.back() == ' ')) {
        cmd.pop_back();
    }
    size_t start = cmd.find_first_not_of(" \t\r\n");
    if (start != std::string::npos) {
        cmd = cmd.substr(start);
    } else {
        return "ERROR: empty command\n";
    }

    if (cmd == "PING") {
        return "PONG\n";
    }
    if (cmd == "VERSION") {
        return "IceBreaker 2.2.0\n";
    }
    if (cmd == "STATUS") {
        size_t count = AppManager::Get().GetUnlockedCount();
        return "OK unlocked=" + std::to_string(count) + "\n";
    }
    if (cmd == "GET_UNLOCKED") {
        std::vector<uint32_t> apps;
        AppManager::Get().GetUnlockedApps(apps);
        std::ostringstream ss;
        for (size_t i = 0; i < apps.size(); ++i) {
            if (i > 0) ss << ",";
            ss << apps[i];
        }
        ss << "\n";
        return ss.str();
    }
    if (cmd == "RELOAD") {
        LuaLoader::ReloadAll();
        return "OK reloaded\n";
    }

    auto parseAppId = [](const std::string& s) -> uint32_t {
        if (s.empty() || s.length() > 10) return 0;
        for (char c : s) {
            if (c < '0' || c > '9') return 0;
        }
        try {
            unsigned long val = std::stoul(s);
            if (val > 0 && val <= 0xFFFFFFFFUL) return static_cast<uint32_t>(val);
        } catch (...) {}
        return 0;
    };

    if (cmd.rfind("RETRY_APP ", 0) == 0 || cmd.rfind("SANITIZE ", 0) == 0) {
        size_t offset = (cmd.rfind("RETRY_APP ", 0) == 0) ? 10 : 9;
        std::string arg = cmd.substr(offset);
        uint32_t appId = parseAppId(arg);
        if (appId == 0) return "ERROR: invalid appId\n";

        PatchEngine::SanitizeAppDownloadState(appId);
        PatchEngine::NotifyLicenseChanged(true);
        HookManager::Log("IPC: sanitized download state and re-armed license for appId " + std::to_string(appId));
        return "OK retried " + std::to_string(appId) + "\n";
    }
    if (cmd.rfind("UNLOCK ", 0) == 0) {
        std::string arg = cmd.substr(7);
        uint32_t appId = parseAppId(arg);
        if (appId == 0) return "ERROR: invalid appId\n";

        AppManager::Get().AddUnlockedApp(appId);
        PatchEngine::NotifyLicenseChanged(true);
        HookManager::Log("IPC: dynamically unlocked appId and notified license refresh for " + std::to_string(appId));
        return "OK unlocked " + std::to_string(appId) + "\n";
    }
    if (cmd.rfind("LOCK ", 0) == 0) {
        std::string arg = cmd.substr(5);
        uint32_t appId = parseAppId(arg);
        if (appId == 0) return "ERROR: invalid appId\n";

        AppManager::Get().RemoveUnlockedApp(appId);
        PatchEngine::NotifyLicenseChanged(true);
        HookManager::Log("IPC: dynamically locked appId and re-armed license for " + std::to_string(appId));
        return "OK locked " + std::to_string(appId) + "\n";
    }

    return "ERROR: unknown command\n";
}

void IpcServer::WorkerThread() {
    HookManager::Log("IPC: named pipe server starting on " + std::string("\\\\.\\pipe\\IceBreaker_IPC"));

    while (s_running.load()) {
        HANDLE hPipe = CreateNamedPipeW(
            kPipeName,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            4096,
            4096,
            0,
            NULL
        );

        if (hPipe == INVALID_HANDLE_VALUE) {
            HookManager::Log("IPC: CreateNamedPipe failed, error: " + std::to_string(GetLastError()));
            Sleep(1000);
            continue;
        }

        s_pipeHandle = hPipe;

        BOOL connected = ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
        if (connected && s_running.load()) {
            char buffer[4096];
            DWORD bytesRead = 0;

            while (s_running.load() && ReadFile(hPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0) {
                buffer[bytesRead] = '\0';
                std::string response = ProcessCommand(buffer);
                DWORD bytesWritten = 0;
                WriteFile(hPipe, response.c_str(), static_cast<DWORD>(response.length()), &bytesWritten, NULL);
                FlushFileBuffers(hPipe);
            }
        }

        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);
        s_pipeHandle = INVALID_HANDLE_VALUE;
    }

    HookManager::Log("IPC: named pipe server stopped.");
}

void IpcServer::Start() {
    if (s_running.exchange(true)) return;
    s_worker = std::thread(WorkerThread);
}

void IpcServer::Stop() {
    if (!s_running.exchange(false)) return;

    if (s_pipeHandle != INVALID_HANDLE_VALUE) {
        CloseHandle(s_pipeHandle);
        s_pipeHandle = INVALID_HANDLE_VALUE;
    }

    // Connect briefly to unblock ConnectNamedPipe if waiting
    HANDLE hClient = CreateFileW(kPipeName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hClient != INVALID_HANDLE_VALUE) {
        CloseHandle(hClient);
    }

    if (s_worker.joinable()) {
        s_worker.join();
    }
}

} // namespace IceBreaker
