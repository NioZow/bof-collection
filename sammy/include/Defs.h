#ifndef DEFS_H
#define DEFS_H

#include <windows.h>
#include <beacon.h>

// pseudo handles
#define NtCurrentProcessToken() ( ( HANDLE ) ( LONG_PTR ) ( -4 ) )
#define NtCurrentThreadToken() ( ( HANDLE ) ( LONG_PTR ) ( -5 ) )

// the impersonation token for the current thread, if it is impersonating; otherwise, the primary token
#define NtCurrentThreadEffectiveToken() ( ( HANDLE ) ( LONG_PTR ) ( -6 ) )

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

// casting macros
#define C_PTR( x )   ( ( PVOID    ) ( x ) )
#define U_PTR( x )   ( ( UINT_PTR ) ( x ) )
#define U_PTR32( x ) ( ( ULONG    ) ( x ) )
#define U_PTR64( x ) ( ( ULONG64  ) ( x ) )
#define A_PTR( x )   ( ( PCHAR    ) ( x ) )
#define W_PTR( x )   ( ( PWCHAR   ) ( x ) )

// dereference memory macros
#define C_DEF( x )   ( * ( PVOID* )  ( x ) )
#define C_DEF08( x ) ( * ( UINT8*  ) ( x ) )
#define C_DEF16( x ) ( * ( UINT16* ) ( x ) )
#define C_DEF32( x ) ( * ( UINT32* ) ( x ) )
#define C_DEF64( x ) ( * ( UINT64* ) ( x ) )

// Hashing defines
#define H_MAGIC_KEY       5381
#define H_MAGIC_SEED      5
#define H_MODULE_NTDLL    0x70e61753
#define H_MODULE_KERNEL32 0xadd31df0

// mem alloc
//#define MemCopy                             __movsb
//#define MemSet                              __stosb

// Memory allocation NTDLL APIs
DECLSPEC_IMPORT NTSYSAPI PVOID NTAPI NTDLL$RtlCreateHeap(
	_In_ ULONG Flags,
	_In_opt_ PVOID HeapBase,
	_In_opt_ SIZE_T ReserveSize,
	_In_opt_ SIZE_T CommitSize,
	_In_opt_ PVOID Lock,
	_When_( ( Flags & HEAP_CREATE_SEGMENT_HEAP ) != 0, _In_reads_bytes_opt_( sizeof( RTL_SEGMENT_HEAP_PARAMETERS ) ) )
	_When_( ( Flags & HEAP_CREATE_SEGMENT_HEAP ) == 0, _In_reads_bytes_opt_( sizeof( RTL_HEAP_PARAMETERS ) ) )
	_In_opt_ PVOID Parameters
);

DECLSPEC_IMPORT NTSYSAPI PVOID NTAPI NTDLL$RtlAllocateHeap(
	PVOID HeapHandle,
	ULONG Flags,
	SIZE_T Size
);

DECLSPEC_IMPORT NTSYSAPI LOGICAL NTDLL$RtlFreeHeap(
	PVOID HeapHandle,
	ULONG Flags,
	PVOID BaseAddress
);

// MSVCRT
WINBASEAPI int __cdecl MSVCRT$printf( const char * __format, ... );

WINBASEAPI size_t __cdecl MSVCRT$wcslen( const wchar_t * _Str );

WINBASEAPI int
__cdecl MSVCRT$_snwprintf( wchar_t * __restrict__ _Dest, size_t _Count, const wchar_t * __restrict__ _Format, ... );

WINBASEAPI int __cdecl MSVCRT$sprintf( char * __stream, const char * __format, ... );

WINBASEAPI int __cdecl MSVCRT$strcmp( const char * _Str1, const char * _Str2 );

WINBASEAPI int __cdecl MSVCRT$strncmp( const char * _Str1, const char * _Str2, size_t _MaxCount );

// errors
//#define PRINT_NT_ERROR( ntapi, status ) MSVCRT$printf("[!] %s failed with error: 0x%04X\n", ntapi, status )
#define PRINT_NT_ERROR( ntapi, status ) BeaconPrintf(CALLBACK_ERROR, "[!] %s failed with error: 0x%04X\n", ntapi, status )
#define PRINT_WIN32_ERROR( win32api ) MSVCRT$printf("[!] %s failed with error: %ld\n", win32api, NtCurrentTeb()->LastErrorValue )

#endif //DEFS_H