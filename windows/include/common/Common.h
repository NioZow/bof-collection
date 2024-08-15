#ifndef COMMON_COMMON_H
#define COMMMON_COMMON_H

#include <windows.h>
#include <common/Native.h>

typedef PVOID ( NTAPI*fnRtlAllocateHeap )(
    IN PVOID          HeapHandle,
    IN OPTIONAL ULONG Flags,
    IN SIZE_T         Size
);

typedef PVOID ( NTAPI*fnRtlReAllocateHeap )(
    IN PVOID          HeapHandle,
    IN ULONG          Flags,
    IN OPTIONAL PVOID BaseAddress,
    IN SIZE_T         Size
);

typedef PVOID ( NTAPI*fnRtlFreeHeap )(
    IN PVOID          HeapHandle,
    IN OPTIONAL ULONG Flags,
    IN OPTIONAL PVOID BaseAddress
);

typedef BOOL ( WINAPI*fnAttachConsole )(
    IN DWORD dwProcessId
);

typedef HANDLE WINAPI ( WINAPI*fnGetStdHandle )(
    IN DWORD nStdHandle
);

typedef BOOL ( WINAPI*fnWriteConsoleA )(
    IN HANDLE            hConsoleOutput,
    IN const PVOID       lpBuffer,
    IN DWORD             nNumberOfCharsToWrite,
    OUT OPTIONAL LPDWORD lpNumberOfCharsWritten,
    LPVOID               lpReserved
);

typedef int ( WINAPI*fnVsnprintf )(
    char *      buffer,
    size_t      count,
    const char *format,
    va_list     argptr
);

typedef PVOID ( WINAPI*fnLoadLibraryA )(
    PCSTR Module
);

typedef INT ( WINAPI*fnMessageBoxA )(
    IN OPTIONAL HWND   hWnd,
    IN OPTIONAL LPCSTR lpText,
    IN OPTIONAL LPCSTR lpCaption,
    IN UINT            uType
);

typedef BOOL ( WINAPI*fnEnumWindows )(
    IN WNDENUMPROC lpEnumFunc,
    IN LPARAM      lParam
);

typedef HWND ( WINAPI*fnGetWindow )(
    IN HWND hWnd,
    IN UINT uCmd
);

typedef HWND ( WINAPI*fnGetTopWindow )(
    IN OPTIONAL HWND hWnd
);

typedef int ( WINAPI*fnGetWindowTextLengthW )(
    IN HWND hWnd
);

typedef BOOL ( WINAPI*fnIsWindowVisible )(
    IN HWND hWnd
);

typedef int ( WINAPI*fnGetWindowTextW )(
    IN HWND    hWnd,
    OUT LPWSTR lpString,
    IN int     nMaxCount
);

typedef DWORD ( WINAPI*fnGetWindowThreadProcessId )(
    IN HWND              hWnd,
    OUT OPTIONAL LPDWORD lpdwProcessId
);

typedef NTSTATUS ( NTAPI*fnNtOpenProcess )(
    OUT PHANDLE            ProcessHandle,
    IN ACCESS_MASK         DesiredAccess,
    IN POBJECT_ATTRIBUTES  ObjectAttributes,
    IN OPTIONAL PCLIENT_ID ClientId
);

typedef NTSTATUS ( NTAPI*fnNtQueryInformationProcess )(
    IN HANDLE           ProcessHandle,
    IN PROCESSINFOCLASS ProcessInformationClass,
    OUT PVOID           ProcessInformation,
    IN ULONG            ProcessInformationLength,
    OUT OPTIONAL PULONG ReturnLength
);

typedef DWORD ( WINAPI*fnGetModuleFileNameW )(
    IN OPTIONAL HMODULE hModule,
    OUT LPWSTR          lpFilename,
    IN DWORD            nSize
);

typedef BOOL ( WINAPI*fnQueryFullProcessImageNameW )(
    IN HANDLE     hProcess,
    IN DWORD      dwFlags,
    OUT LPWSTR    lpExeName,
    IN OUT PDWORD lpdwSize
);

typedef NTSTATUS ( NTAPI*fnNtQuerySystemInformation )(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    OUT OPTIONAL PVOID          SystemInformation,
    IN ULONG                    SystemInformationLength,
    OUT OPTIONAL PULONG         ReturnLength
);

#endif //COMMON_COMMON_H
