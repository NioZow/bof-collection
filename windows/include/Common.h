#ifndef COMMON_COMMON_H
#define COMMMON_COMMON_H

#include <windows.h>
#include <beacon.h>
#include <Native.h>

//
// pseudo handles
//
#define NtCurrentProcess()              ( ( HANDLE ) ( LONG_PTR ) ( -1 ) )
#define NtCurrentThread()               ( ( HANDLE ) ( LONG_PTR ) ( -2 ) )
#define NtCurrentProcessToken()         ( ( HANDLE ) ( LONG_PTR ) ( -4 ) )
#define NtCurrentThreadToken()          ( ( HANDLE ) ( LONG_PTR ) ( -5 ) )
#define NtCurrentThreadEffectiveToken() ( ( HANDLE ) ( LONG_PTR ) ( -6 ) )

//
// peb/teb related macros
//
#define NtLastError()                   ( NtCurrentTeb()->LastErrorValue  )
#define NtLastStatus()	                ( NtCurrentTeb()->LastStatusValue )
#define NtCurrentHeap()                 ( ( PVOID ) NtCurrentPeb()->ProcessHeap )
#define NtProcessHeap()                 NtCurrentHeap()
#define ZwCurrentProcess()              NtCurrentProcess()
#define ZwCurrentThread()               NtCurrentThread()
#define NtProcessImage()                ( PWCHAR ) NtCurrentPeb()->ProcessParameters->ImagePathName.Buffer
#define NtProcessCurrentDirectory()     ( PWCHAR ) NtCurrentPeb()->ProcessParameters->CurrentDirectory.DosPath

#if _WIN64
#define NtCurrentProcessId() ( ( DWORD ) ( __readgsdword( 0x40 ) ) )
#elif _WIN32
#define NtCurrentProcessId() ( ( DWORD ) ( __readfsdword( 0x20 ) ) )
#endif

#if _WIN64
#define NtCurrentThreadId() ( ( DWORD ) ( __readgsdword( 0x48 ) ) )
#elif _WIN32
#define NtCurrentThreadId() ( ( DWORD ) ( __readgsdword( 0x24 ) ) )
#endif

//
// compiler macros
//
#define INLINE        inline
#define ALWAYS_INLINE [[gnu::always_inline]]
#define NO_INLINE     __attribute__ ((noinline))

//
// casting macros
//
#define C_PTR( x )   ( ( PVOID    ) ( x ) )
#define C_BYTE( x )  ( ( PBYTE    ) ( x ) )
#define U_PTR( x )   ( ( UINT_PTR ) ( x ) )
#define U_PTR32( x ) ( ( ULONG    ) ( x ) )
#define U_PTR64( x ) ( ( ULONG64  ) ( x ) )
#define A_PTR( x )   ( ( PCHAR    ) ( x ) )
#define W_PTR( x )   ( ( PWCHAR   ) ( x ) )

//
// dereference memory macros
//
#define C_DEF( x )   ( * ( PVOID* )  ( x ) )
#define C_DEF08( x ) ( * ( UINT8*  ) ( x ) )
#define C_DEF16( x ) ( * ( UINT16* ) ( x ) )
#define C_DEF32( x ) ( * ( UINT32* ) ( x ) )
#define C_DEF64( x ) ( * ( UINT64* ) ( x ) )

//
// io macros
//
#define PRINTF( text, ... )             BeaconPrintf( CALLBACK_OUTPUT, text, ##__VA_ARGS__ )
#define PRINTF_INFO( text, ... )        PRINTF( text, ##__VA_ARGS__ )
#define PRINTF_ERROR( text, ... )       BeaconPrintf( CALLBACK_ERROR, text, ##__VA_ARGS__ )
#define PRINT_NT_ERROR( ntapi, status ) PRINTF_ERROR( "%s failed with error: 0x%08X\n", ntapi, status )
#define PRINT_WIN32_ERROR( win32api )   PRINTF_ERROR( "%s failed with error: %ld\n", win32api, NtLastError() )

#ifdef IMPERIUM_DEBUG
#define PRINTF_DEBUG( text, ... )       PRINTF( "[DEBUG::%s::%s::%d] " text "\n", __TIME__, __FUNCTION__, __LINE__, ##__VA_ARGS__ )
#else
#define PRINTF_DEBUG( text, ... )
#endif

//
// string
//
#define INIT_ANSI_STRING( str )     { .Length = sizeof( str ) - sizeof( CHAR ), .MaximumLength = sizeof( str ), .Buffer = str }
#define INIT_UNICODE_STRING( wstr ) { .Length = sizeof( wstr ) - sizeof( WCHAR ), .MaximumLength = sizeof( wstr ), .Buffer = wstr }

DECLSPEC_IMPORT PVOID NTAPI NTDLL$RtlAllocateHeap(
    IN PVOID          HeapHandle,
    IN OPTIONAL ULONG Flags,
    IN SIZE_T         Size
);

DECLSPEC_IMPORT PVOID NTAPI NTDLL$RtlReAllocateHeap(
    IN PVOID          HeapHandle,
    IN ULONG          Flags,
    IN OPTIONAL PVOID BaseAddress,
    IN SIZE_T         Size
);

DECLSPEC_IMPORT PVOID NTAPI NTDLL$RtlFreeHeap(
    IN PVOID          HeapHandle,
    IN OPTIONAL ULONG Flags,
    IN OPTIONAL PVOID BaseAddress
);

DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtQuerySystemInformation(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    OUT OPTIONAL PVOID          SystemInformation,
    IN ULONG                    SystemInformationLength,
    OUT OPTIONAL PULONG         ReturnLength
);

DECLSPEC_IMPORT HWND WINAPI USER32$GetWindow(
    IN HWND hWnd,
    IN UINT uCmd
);

DECLSPEC_IMPORT HWND WINAPI USER32$GetTopWindow(
    IN OPTIONAL HWND hWnd
);

DECLSPEC_IMPORT INT WINAPI USER32$GetWindowTextLengthW(
    IN HWND hWnd
);

DECLSPEC_IMPORT BOOL WINAPI USER32$IsWindowVisible(
    IN HWND hWnd
);

DECLSPEC_IMPORT INT WINAPI USER32$GetWindowTextW(
    IN HWND    hWnd,
    OUT LPWSTR lpString,
    IN INT     nMaxCount
);

DECLSPEC_IMPORT DWORD WINAPI USER32$GetWindowThreadProcessId(
    IN HWND              hWnd,
    OUT OPTIONAL LPDWORD lpdwProcessId
);

#endif //COMMON_COMMON_H
