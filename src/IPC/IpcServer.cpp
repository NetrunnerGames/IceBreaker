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
static HANDLE s_stopEvent = NULL;

static std::string TrimWhitespace(const std::string& s) {
    size_t start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    size_t end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

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

    // Trim leading/trailing whitespace and newlines
    std::string cmd = TrimWhitespace(raw);
    if (cmd.empty()) {
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
        std::string arg = TrimWhitespace(cmd.substr(offset));
        uint32_t appId = parseAppId(arg);
        if (appId == 0) return "ERROR: invalid appId\n";

        PatchEngine::SanitizeAppDownloadState(appId);
        PatchEngine::NotifyLicenseChanged(true);
        HookManager::Log("IPC: sanitized download state and re-armed license for appId " + std::to_string(appId));
        return "OK retried " + std::to_string(appId) + "\n";
    }
    if (cmd.rfind("UNLOCK ", 0) == 0) {
        std::string arg = TrimWhitespace(cmd.substr(7));
        uint32_t appId = parseAppId(arg);
        if (appId == 0) return "ERROR: invalid appId\n";

        AppManager::Get().AddUnlockedApp(appId);
        PatchEngine::NotifyLicenseChanged(true);
        HookManager::Log("IPC: dynamically unlocked appId and notified license refresh for " + std::to_string(appId));
        return "OK unlocked " + std::to_string(appId) + "\n";
    }
    if (cmd.rfind("LOCK ", 0) == 0) {
        std::string arg = TrimWhitespace(cmd.substr(5));
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

    HANDLE hIoEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!hIoEvent) {
        HookManager::Log("IPC: CreateEvent failed, stopping worker.");
        return;
    }

    HANDLE hPipe = INVALID_HANDLE_VALUE;

    while (s_running.load()) {
        if (hPipe == INVALID_HANDLE_VALUE) {
            hPipe = CreateNamedPipeW(
                kPipeName,
                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                4096,
                4096,
                0,
                NULL
            );

            if (hPipe == INVALID_HANDLE_VALUE) {
                HookManager::Log("IPC: CreateNamedPipe failed, error: " + std::to_string(GetLastError()));
                if (s_stopEvent) {
                    WaitForSingleObject(s_stopEvent, 1000);
                } else {
                    Sleep(1000);
                }
                continue;
            }
        }

        OVERLAPPED ov{};
        ov.hEvent = hIoEvent;
        ResetEvent(hIoEvent);

        bool connected = false;
        if (ConnectNamedPipe(hPipe, &ov)) {
            connected = true;
        } else {
            DWORD err = GetLastError();
            if (err == ERROR_PIPE_CONNECTED) {
                connected = true;
            } else if (err == ERROR_IO_PENDING) {
                HANDLE waitHandles[2] = { s_stopEvent, hIoEvent };
                DWORD waitCount = s_stopEvent ? 2 : 1;
                DWORD waitIdx = s_stopEvent ? WaitForMultipleObjects(waitCount, waitHandles, FALSE, INFINITE)
                                            : WaitForSingleObject(hIoEvent, INFINITE);
                if (s_stopEvent && waitIdx == WAIT_OBJECT_0) {
                    CancelIoEx(hPipe, &ov);
                    DWORD unused = 0;
                    GetOverlappedResult(hPipe, &ov, &unused, TRUE);
                } else if ((!s_stopEvent && waitIdx == WAIT_OBJECT_0) ||
                           (s_stopEvent && waitIdx == WAIT_OBJECT_0 + 1)) {
                    DWORD unused = 0;
                    connected = GetOverlappedResult(hPipe, &ov, &unused, FALSE) != FALSE;
                }
            } else {
                CloseHandle(hPipe);
                hPipe = INVALID_HANDLE_VALUE;
                continue;
            }
        }

        if (connected && s_running.load()) {
            char buffer[4096];
            while (s_running.load()) {
                OVERLAPPED readOv{};
                readOv.hEvent = hIoEvent;
                ResetEvent(hIoEvent);

                DWORD bytesRead = 0;
                BOOL readOk = ReadFile(hPipe, buffer, sizeof(buffer) - 1, &bytesRead, &readOv);
                if (!readOk) {
                    DWORD err = GetLastError();
                    if (err == ERROR_IO_PENDING) {
                        HANDLE waitHandles[2] = { s_stopEvent, hIoEvent };
                        DWORD waitCount = s_stopEvent ? 2 : 1;
                        DWORD waitIdx = s_stopEvent ? WaitForMultipleObjects(waitCount, waitHandles, FALSE, INFINITE)
                                                    : WaitForSingleObject(hIoEvent, INFINITE);
                        if (s_stopEvent && waitIdx == WAIT_OBJECT_0) {
                            CancelIoEx(hPipe, &readOv);
                            GetOverlappedResult(hPipe, &readOv, &bytesRead, TRUE);
                            break;
                        }
                        if (!GetOverlappedResult(hPipe, &readOv, &bytesRead, FALSE)) {
                            break;
                        }
                    } else {
                        break;
                    }
                }
                if (bytesRead == 0) break;

                buffer[bytesRead] = '\0';
                std::string response = ProcessCommand(buffer);

                OVERLAPPED writeOv{};
                writeOv.hEvent = hIoEvent;
                ResetEvent(hIoEvent);
                DWORD bytesWritten = 0;
                BOOL writeOk = WriteFile(hPipe, response.c_str(), static_cast<DWORD>(response.length()), &bytesWritten, &writeOv);
                if (!writeOk) {
                    DWORD err = GetLastError();
                    if (err == ERROR_IO_PENDING) {
                        HANDLE waitHandles[2] = { s_stopEvent, hIoEvent };
                        DWORD waitCount = s_stopEvent ? 2 : 1;
                        DWORD waitIdx = s_stopEvent ? WaitForMultipleObjects(waitCount, waitHandles, FALSE, INFINITE)
                                                    : WaitForSingleObject(hIoEvent, INFINITE);
                        if (s_stopEvent && waitIdx == WAIT_OBJECT_0) {
                            CancelIoEx(hPipe, &writeOv);
                            GetOverlappedResult(hPipe, &writeOv, &bytesWritten, TRUE);
                            break;
                        }
                        if (!GetOverlappedResult(hPipe, &writeOv, &bytesWritten, FALSE)) {
                            break;
                        }
                    } else {
                        break;
                    }
                }
            }
        }

        if (!DisconnectNamedPipe(hPipe)) {
            CloseHandle(hPipe);
            hPipe = INVALID_HANDLE_VALUE;
        }
    }

    if (hPipe != INVALID_HANDLE_VALUE) {
        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);
    }

    CloseHandle(hIoEvent);
    HookManager::Log("IPC: named pipe server stopped.");
}

void IpcServer::Start() {
    if (s_running.exchange(true)) return;
    if (!s_stopEvent) {
        s_stopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    } else {
        ResetEvent(s_stopEvent);
    }
    s_worker = std::thread(WorkerThread);
}

void IpcServer::Stop() {
    if (!s_running.exchange(false)) return;

    if (s_stopEvent) {
        SetEvent(s_stopEvent);
    }

    if (s_worker.joinable()) {
        s_worker.join();
    }

    if (s_stopEvent) {
        CloseHandle(s_stopEvent);
        s_stopEvent = NULL;
    }
}

} // namespace IceBreaker
