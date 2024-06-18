#ifndef DEFS_H
#define DEFS_H

#include <windows.h>
#include <beacon.h>
#include <bofdefs.h>

// pseudo handles
#define NtCurrentProcessToken() ( ( HANDLE ) ( LONG_PTR ) ( -4 ) )
#define NtCurrentThreadToken() ( ( HANDLE ) ( LONG_PTR ) ( -5 ) )

// the impersonation token for the current thread, if it is impersonating; otherwise, the primary token
#define NtCurrentThreadEffectiveToken() ( ( HANDLE ) ( LONG_PTR ) ( -6 ) )

#if _WIN64
#define NtCurrentProcessId() ( ( DWORD ) ( __readgsdword( 0x40 ) ) )
#elif _WIN32
#define NtCurrentProcessId() ( ( DWORD ) ( __readfsdword( 0x20 ) ) )
#else
#define NtCurrentProcessId() ( ( DWORD ) ( 0 ) )
#endif

#if _WIN64
#define NtCurrentThreadId() ( ( DWORD ) ( __readgsdword( 0x48 ) ) )
#elif _WIN32
#define NtCurrentThreadId() ( ( DWORD ) ( __readgsdword( 0x24 ) ) )
#else
#define NtCurrentThreadId() ( ( DWORD ) ( 0 ) )
#endif

// errors
#define PRINT_NT_ERROR( ntapi, status ) internal_printf("[!] %s failed with error: 0x%04X\n", ntapi, status )

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

#endif //DEFS_H