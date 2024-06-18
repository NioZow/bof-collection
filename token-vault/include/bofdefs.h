#ifndef BOFDEFS_H
#define BOFDEFS_H

#include <Internals.h>

#pragma intrinsic(memcmp, memcpy, strcpy, strcmp, _stricmp, strlen)

#include <windows.h>
#include <process.h>
#include <imagehlp.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <windns.h>
#include <dbghelp.h>
#include <winldap.h>
#include <winnetwk.h>
#include <wtsapi32.h>
#include <shlwapi.h>

//NTDLL
NTSYSCALLAPI NTSTATUS NTAPI NTDLL$NtCreateFile(
	PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock,
	PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition,
	ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength
);

NTSYSCALLAPI NTSTATUS NTAPI NTDLL$NtClose( HANDLE Handle );

NTSYSCALLAPI NTSTATUS NTAPI NTDLL$NtFsControlFile(
	HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock,
	ULONG IoControlCode, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength
);

NTSYSCALLAPI NTSTATUS NTAPI NTDLL$NtOpenProcess(
	_Out_ PHANDLE ProcessHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ PCLIENT_ID ClientId
);

NTSYSCALLAPI NTSTATUS NTAPI NTDLL$NtOpenProcessTokenEx(
	_In_ HANDLE ProcessHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ ULONG HandleAttributes,
	_Out_ PHANDLE TokenHandle
);

NTSYSCALLAPI NTSTATUS NTAPI NTDLL$NtOpenThreadTokenEx(
	_In_ HANDLE ThreadHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ BOOLEAN OpenAsSelf,
	_In_ ULONG HandleAttributes,
	_Out_ PHANDLE TokenHandle
);

NTSYSCALLAPI NTSTATUS NTAPI NTDLL$NtQueryInformationToken(
	_In_ HANDLE TokenHandle,
	_In_ TOKEN_INFORMATION_CLASS TokenInformationClass,
	_Out_writes_bytes_to_opt_( TokenInformationLength, * ReturnLength ) PVOID TokenInformation,
	_In_ ULONG TokenInformationLength,
	_Out_ PULONG ReturnLength
);

NTSYSCALLAPI NTSTATUS NTAPI NTDLL$NtQuerySystemInformation(
	_In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
	_Out_writes_bytes_opt_( SystemInformationLength ) PVOID SystemInformation,
	_In_ ULONG SystemInformationLength,
	_Out_opt_ PULONG ReturnLength
);

NTSYSCALLAPI NTSTATUS NTAPI NTDLL$NtDuplicateToken(
	_In_ HANDLE ExistingTokenHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_ BOOLEAN EffectiveOnly,
	_In_ TOKEN_TYPE Type,
	_Out_ PHANDLE NewTokenHandle
);

NTSYSCALLAPI NTSTATUS NTAPI NTDLL$NtSetInformationToken(
	_In_ HANDLE TokenHandle,
	_In_ TOKEN_INFORMATION_CLASS TokenInformationClass,
	_In_reads_bytes_( TokenInformationLength ) PVOID TokenInformation,
	_In_ ULONG TokenInformationLength
);

NTSYSCALLAPI NTSTATUS NTAPI NTDLL$NtSetInformationThread(
	_In_ HANDLE ThreadHandle,
	_In_ THREADINFOCLASS ThreadInformationClass,
	_In_reads_bytes_( ThreadInformationLength ) PVOID ThreadInformation,
	_In_ ULONG ThreadInformationLength
);

NTSYSAPI NTSTATUS NTAPI NTDLL$RtlConvertSidToUnicodeString(
	_Inout_ PUNICODE_STRING UnicodeString,
	_In_ PSID Sid,
	_In_ BOOLEAN AllocateDestinationString
);

NTSYSAPI VOID NTAPI NTDLL$RtlFreeUnicodeString(
	_Inout_ _At_( UnicodeString->Buffer, _Frees_ptr_opt_ ) PUNICODE_STRING UnicodeString
);

NTSYSAPI PVOID NTAPI NTDLL$RtlCreateHeap(
	_In_ ULONG Flags,
	_In_opt_ PVOID HeapBase,
	_In_opt_ SIZE_T ReserveSize,
	_In_opt_ SIZE_T CommitSize,
	_In_opt_ PVOID Lock,
	_When_( ( Flags & HEAP_CREATE_SEGMENT_HEAP ) != 0, _In_reads_bytes_opt_( sizeof( RTL_SEGMENT_HEAP_PARAMETERS ) ) )
	_When_( ( Flags & HEAP_CREATE_SEGMENT_HEAP ) == 0, _In_reads_bytes_opt_( sizeof( RTL_HEAP_PARAMETERS ) ) )
	_In_opt_ PVOID Parameters
);

// Toke
NTSYSCALLAPI NTSTATUS NTAPI NTDLL$NtCreateToken(
	_Out_ PHANDLE TokenHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_ TOKEN_TYPE Type,
	_In_ PLUID AuthenticationId,
	_In_ PLARGE_INTEGER ExpirationTime,
	_In_ PTOKEN_USER User,
	_In_ PTOKEN_GROUPS Groups,
	_In_ PTOKEN_PRIVILEGES Privileges,
	_In_opt_ PTOKEN_OWNER Owner,
	_In_ PTOKEN_PRIMARY_GROUP PrimaryGroup,
	_In_opt_ PTOKEN_DEFAULT_DACL DefaultDacl,
	_In_ PTOKEN_SOURCE Source
);

NTSYSCALLAPI NTSTATUS NTAPI NTDLL$NtCreateTokenEx(
	_Out_ PHANDLE TokenHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_ TOKEN_TYPE Type,
	_In_ PLUID AuthenticationId,
	_In_ PLARGE_INTEGER ExpirationTime,
	_In_ PTOKEN_USER User,
	_In_ PTOKEN_GROUPS Groups,
	_In_ PTOKEN_PRIVILEGES Privileges,
	_In_opt_ PTOKEN_SECURITY_ATTRIBUTES_INFORMATION UserAttributes,
	_In_opt_ PTOKEN_SECURITY_ATTRIBUTES_INFORMATION DeviceAttributes,
	_In_opt_ PTOKEN_GROUPS DeviceGroups,
	_In_opt_ PTOKEN_MANDATORY_POLICY MandatoryPolicy,
	_In_opt_ PTOKEN_OWNER Owner,
	_In_ PTOKEN_PRIMARY_GROUP PrimaryGroup,
	_In_opt_ PTOKEN_DEFAULT_DACL DefaultDacl,
	_In_ PTOKEN_SOURCE Source
);

NTSYSAPI NTSTATUS NTAPI NTDLL$RtlAllocateAndInitializeSid(
	_In_ PSID_IDENTIFIER_AUTHORITY IdentifierAuthority,
	_In_ UCHAR SubAuthorityCount,
	_In_ ULONG SubAuthority0,
	_In_ ULONG SubAuthority1,
	_In_ ULONG SubAuthority2,
	_In_ ULONG SubAuthority3,
	_In_ ULONG SubAuthority4,
	_In_ ULONG SubAuthority5,
	_In_ ULONG SubAuthority6,
	_In_ ULONG SubAuthority7,
	_Outptr_ PSID * Sid
);

NTSYSAPI LUID NTAPI NTDLL$RtlConvertUlongToLuid(
	ULONG Ulong
);


//KERNEL32
WINBASEAPI void *
WINAPI KERNEL32$VirtualAlloc( LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect );

WINBASEAPI int WINAPI KERNEL32$VirtualFree( LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType );

DECLSPEC_IMPORT HLOCAL WINAPI KERNEL32$LocalAlloc( UINT, SIZE_T );

DECLSPEC_IMPORT HLOCAL WINAPI KERNEL32$LocalFree( HLOCAL );

WINBASEAPI void * WINAPI KERNEL32$HeapAlloc( HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes );

WINBASEAPI LPVOID WINAPI KERNEL32$HeapReAlloc( HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes );

WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap();

WINBASEAPI BOOL WINAPI KERNEL32$HeapFree( HANDLE, DWORD, PVOID );

WINBASEAPI DWORD WINAPI KERNEL32$FormatMessageA(
	DWORD dwFlags, LPCVOID lpSource, DWORD dwMessageId, DWORD dwLanguageId, LPSTR lpBuffer, DWORD nSize,
	va_list * Arguments
);

WINBASEAPI int WINAPI Kernel32$WideCharToMultiByte(
	UINT CodePage, DWORD dwFlags, LPCWCH lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte,
	LPCCH lpDefaultChar, LPBOOL lpUsedDefaultChar
);

WINBASEAPI int WINAPI KERNEL32$FileTimeToLocalFileTime( CONST FILETIME * lpFileTime, LPFILETIME lpLocalFileTime );

WINBASEAPI int WINAPI KERNEL32$FileTimeToSystemTime( CONST FILETIME * lpFileTime, LPSYSTEMTIME lpSystemTime );

WINBASEAPI int WINAPI KERNEL32$GetDateFormatW(
	LCID Locale, DWORD dwFlags, CONST SYSTEMTIME * lpDate, LPCWSTR lpFormat, LPWSTR lpDateStr, int cchDate
);

WINBASEAPI VOID WINAPI KERNEL32$GetSystemTimeAsFileTime( LPFILETIME lpSystemTimeAsFileTime );

WINBASEAPI VOID WINAPI KERNEL32$GetLocalTime( LPSYSTEMTIME lpSystemTime );

WINBASEAPI WINBOOL WINAPI KERNEL32$SystemTimeToFileTime( CONST SYSTEMTIME * lpSystemTime, LPFILETIME lpFileTime );

WINBASEAPI WINBOOL WINAPI KERNEL32$SystemTimeToTzSpecificLocalTime(
	CONST TIME_ZONE_INFORMATION * lpTimeZoneInformation, CONST SYSTEMTIME * lpUniversalTime, LPSYSTEMTIME lpLocalTime
);

WINBASEAPI WINBOOL WINAPI KERNEL32$GlobalMemoryStatusEx( LPMEMORYSTATUSEX lpBuffer );

WINBASEAPI WINBOOL WINAPI KERNEL32$GetDiskFreeSpaceExA(
	LPCSTR lpDirectoryName, PULARGE_INTEGER lpFreeBytesAvailableToCaller, PULARGE_INTEGER lpTotalNumberOfBytes,
	PULARGE_INTEGER lpTotalNumberOfFreeBytes
);

WINBASEAPI HANDLE WINAPI KERNEL32$GetCurrentProcess( VOID );

DECLSPEC_IMPORT DWORD KERNEL32$GetCurrentProcessId( VOID );

WINBASEAPI DWORD WINAPI KERNEL32$GetLastError( VOID );

WINBASEAPI WINBOOL WINAPI KERNEL32$CloseHandle( HANDLE hObject );

WINBASEAPI HANDLE WINAPI KERNEL32$CreateThread(
	LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress,
	LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId
);

WINBASEAPI DWORD WINAPI KERNEL32$GetTickCount( VOID );

WINBASEAPI ULONGLONG WINAPI KERNEL32$GetTickCount64( VOID );

WINBASEAPI LPVOID
WINAPI KERNEL32$CreateFiber( SIZE_T dwStackSize, LPFIBER_START_ROUTINE lpStartAddress, LPVOID lpParameter );

WINBASEAPI LPVOID WINAPI KERNEL32$ConvertThreadToFiber( LPVOID lpParameter );

WINBASEAPI WINBOOL WINAPI KERNEL32$ConvertFiberToThread( VOID );

WINBASEAPI VOID WINAPI KERNEL32$DeleteFiber( LPVOID lpFiber );

WINBASEAPI VOID WINAPI KERNEL32$SwitchToFiber( LPVOID lpFiber );

WINBASEAPI DWORD WINAPI KERNEL32$WaitForSingleObject( HANDLE hHandle, DWORD dwMilliseconds );

WINBASEAPI VOID WINAPI KERNEL32$Sleep( DWORD dwMilliseconds );

WINBASEAPI WINBOOL WINAPI KERNEL32$DeleteFileW( LPCWSTR lpFileName );

WINBASEAPI HANDLE WINAPI KERNEL32$CreateFileW(
	LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile
);

WINBASEAPI DWORD WINAPI KERNEL32$GetFileSize( HANDLE hFile, LPDWORD lpFileSizeHigh );

WINBASEAPI WINBOOL WINAPI KERNEL32$ReadFile(
	HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped
);

WINBASEAPI HANDLE WINAPI KERNEL32$OpenProcess( DWORD dwDesiredAccess, WINBOOL bInheritHandle, DWORD dwProcessId );

WINBASEAPI WINBOOL WINAPI KERNEL32$GetComputerNameExW( COMPUTER_NAME_FORMAT NameType, LPWSTR lpBuffer, LPDWORD nSize );

WINBASEAPI int WINAPI KERNEL32$lstrlenW( LPCWSTR lpString );

WINBASEAPI LPWSTR WINAPI KERNEL32$lstrcatW( LPWSTR lpString1, LPCWSTR lpString2 );

WINBASEAPI LPWSTR WINAPI KERNEL32$lstrcpynW( LPWSTR lpString1, LPCWSTR lpString2, int iMaxLength );

WINBASEAPI DWORD
WINAPI KERNEL32$GetFullPathNameW( LPCWSTR lpFileName, DWORD nBufferLength, LPWSTR lpBuffer, LPWSTR * lpFilePart );

WINBASEAPI DWORD WINAPI KERNEL32$GetFileAttributesW( LPCWSTR lpFileName );

WINBASEAPI DWORD WINAPI KERNEL32$GetCurrentDirectoryW( DWORD nBufferLength, LPWSTR lpBuffer );

WINBASEAPI HANDLE WINAPI KERNEL32$FindFirstFileW( LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData );

WINBASEAPI HANDLE WINAPI KERNEL32$FindFirstFileA( char * lpFileName, LPWIN32_FIND_DATA lpFindFileData );

WINBASEAPI WINBOOL WINAPI KERNEL32$FindNextFileW( HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData );

WINBASEAPI WINBOOL WINAPI KERNEL32$FindNextFileA( HANDLE hFindFile, LPWIN32_FIND_DATA lpFindFileData );

WINBASEAPI WINBOOL WINAPI KERNEL32$FindClose( HANDLE hFindFile );

WINBASEAPI VOID WINAPI KERNEL32$SetLastError( DWORD dwErrCode );

#define intAlloc( size ) KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, size)
#define intRealloc( ptr, size ) (ptr) ? KERNEL32$HeapReAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, ptr, size) : KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, size)
#define intFree( addr ) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, addr)
#define intZeroMemory( addr, size ) MSVCRT$memset((addr),0,size)

DECLSPEC_IMPORT HGLOBAL KERNEL32$GlobalAlloc( UINT uFlags, SIZE_T dwBytes );

DECLSPEC_IMPORT HGLOBAL KERNEL32$GlobalFree( HGLOBAL hMem );

DECLSPEC_IMPORT LPTCH WINAPI KERNEL32$GetEnvironmentStrings();

DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$FreeEnvironmentStringsA( LPSTR );

WINBASEAPI DWORD WINAPI KERNEL32$ExpandEnvironmentStringsW( LPCWSTR lpSrc, LPWSTR lpDst, DWORD nSize );

WINBASEAPI HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot( DWORD dwFlags, DWORD th32ProcessID );

WINBASEAPI WINBOOL WINAPI KERNEL32$Process32First( HANDLE hSnapshot, LPPROCESSENTRY32 lppe );

WINBASEAPI WINBOOL WINAPI KERNEL32$Process32Next( HANDLE hSnapshot, LPPROCESSENTRY32 lppe );

WINBASEAPI WINBOOL WINAPI KERNEL32$Module32First( HANDLE hSnapshot, LPMODULEENTRY32 lpme );

WINBASEAPI WINBOOL WINAPI KERNEL32$Module32Next( HANDLE hSnapshot, LPMODULEENTRY32 lpme );

WINBASEAPI HMODULE WINAPI KERNEL32$LoadLibraryA( LPCSTR lpLibFileName );

WINBASEAPI FARPROC WINAPI KERNEL32$GetProcAddress( HMODULE hModule, LPCSTR lpProcName );

WINBASEAPI WINBOOL WINAPI KERNEL32$FreeLibrary( HMODULE hLibModule );

DECLSPEC_IMPORT WINBASEAPI int WINAPI KERNEL32$lstrlenA( LPCSTR );

DECLSPEC_IMPORT int
WINAPI KERNEL32$GetLocaleInfoEx( LPCWSTR lpLocaleName, LCTYPE LCType, LPWSTR lpLCData, int cchData );

WINBASEAPI int WINAPI KERNEL32$GetSystemDefaultLocaleName( LPCWSTR lpLocaleName, int cchLocaleName );

DECLSPEC_IMPORT LCID WINAPI KERNEL32$LocaleNameToLCID( LPCWSTR lpName, DWORD dwFlags );

DECLSPEC_IMPORT int WINAPI KERNEL32$GetDateFormatEx(
	LPCWSTR lpLocaleName, DWORD dwFlags, const SYSTEMTIME * lpData, LPCWSTR lpFormat, LPWSTR lpDateStr, int cchDate,
	LPCWSTR lpCalendar
);


//WTSAPI32
DECLSPEC_IMPORT DWORD WINAPI WTSAPI32$WTSEnumerateSessionsA( LPVOID, DWORD, DWORD, PWTS_SESSION_INFO *, DWORD * );

DECLSPEC_IMPORT DWORD WINAPI WTSAPI32$WTSQuerySessionInformationA( LPVOID, DWORD, WTS_INFO_CLASS, LPSTR *, DWORD * );

DECLSPEC_IMPORT DWORD WINAPI WTSAPI32$WTSFreeMemory( PVOID );

//Iphlpapi.lib
//ULONG WINAPI IPHLPAPI$GetAdaptersInfo (PIP_ADAPTER_INFO AdapterInfo, PULONG SizePointer);
DECLSPEC_IMPORT DWORD WINAPI IPHLPAPI$GetAdaptersInfo( PIP_ADAPTER_INFO, PULONG );

DECLSPEC_IMPORT DWORD
WINAPI IPHLPAPI$GetIpForwardTable( PMIB_IPFORWARDTABLE pIpForwardTable, PULONG pdwSize, WINBOOL bOrder );

DECLSPEC_IMPORT DWORD WINAPI IPHLPAPI$GetNetworkParams( PFIXED_INFO, PULONG );

DECLSPEC_IMPORT ULONG WINAPI IPHLPAPI$GetUdpTable( PMIB_UDPTABLE UdpTable, PULONG SizePointer, WINBOOL Order );

DECLSPEC_IMPORT ULONG WINAPI IPHLPAPI$GetTcpTable( PMIB_TCPTABLE TcpTable, PULONG SizePointer, WINBOOL Order );

DECLSPEC_IMPORT ULONG WINAPI IPHLPAPI$GetIpNetTable( PMIB_IPNETTABLE IpNetTable, PULONG SizePointer, BOOL Order );

//MSVCRT
WINBASEAPI char * __cdecl MSVCRT$_ultoa( unsigned long _Value, char * _Dest, int _Radix );

WINBASEAPI void * __cdecl MSVCRT$calloc( size_t _NumOfElements, size_t _SizeOfElements );

WINBASEAPI void * __cdecl MSVCRT$memcpy( void * __restrict__ _Dst, const void * __restrict__ _Src, size_t _MaxCount );

WINBASEAPI int __cdecl MSVCRT$memcmp( const void * _Buf1, const void * _Buf2, size_t _Size );

WINBASEAPI void * __cdecl MSVCRT$realloc( void * _Memory, size_t _NewSize );

WINBASEAPI void __cdecl MSVCRT$free( void * _Memory );

WINBASEAPI void __cdecl MSVCRT$memset( void * dest, int c, size_t count );

WINBASEAPI int __cdecl MSVCRT$sprintf( char * __stream, const char * __format, ... );

WINBASEAPI int __cdecl MSVCRT$printf( const char * __format, ... );

WINBASEAPI int
__cdecl MSVCRT$vsnprintf( char * __restrict__ d, size_t n, const char * __restrict__ format, va_list arg );

WINBASEAPI int
__cdecl MSVCRT$_snwprintf( wchar_t * __restrict__ _Dest, size_t _Count, const wchar_t * __restrict__ _Format, ... );

WINBASEAPI errno_t __cdecl MSVCRT$wcscpy_s( wchar_t * _Dst, rsize_t _DstSize, const wchar_t * _Src );

WINBASEAPI size_t __cdecl MSVCRT$wcslen( const wchar_t * _Str );

WINBASEAPI size_t
__cdecl MSVCRT$wcstombs( char * __restrict__ _Dest, const wchar_t * __restrict__ _Source, size_t _MaxCount );

WINBASEAPI wchar_t * __cdecl MSVCRT$wcscmp( const wchar_t * _lhs, const wchar_t * _rhs );

WINBASEAPI wchar_t * __cdecl MSVCRT$wcstok( wchar_t * __restrict__ _Str, const wchar_t * __restrict__ _Delim );

WINBASEAPI wchar_t * __cdecl MSVCRT$wcstok_s( wchar_t * _Str, const wchar_t * _Delim, wchar_t ** _Context );

WINBASEAPI wchar_t * __cdecl MSVCRT$wcsstr( const wchar_t * _Str, const wchar_t * _SubStr );

WINBASEAPI wchar_t * __cdecl MSVCRT$wcscat( wchar_t * __restrict__ _Dest, const wchar_t * __restrict__ _Source );

WINBASEAPI wchar_t *
__cdecl MSVCRT$wcsncat( wchar_t * __restrict__ _Dest, const wchar_t * __restrict__ _Source, size_t _Count );

WINBASEAPI wchar_t *
__cdecl MSVCRT$strncat( char * __restrict__ _Dest, const char * __restrict__ _Source, size_t _Count );

WINBASEAPI wchar_t * __cdecl MSVCRT$wcscpy( wchar_t * __restrict__ _Dest, const wchar_t * __restrict__ _Source );

WINBASEAPI int __cdecl MSVCRT$_wcsicmp( const wchar_t * _Str1, const wchar_t * _Str2 );

WINBASEAPI int __cdecl MSVCRT$_wcsnicmp( const wchar_t * _Str1, const wchar_t * _Str2, size_t _Count );

WINBASEAPI int __cdecl MSVCRT$_strnicmp( const char * _Str1, const char * _Str2, size_t _Count );

WINBASEAPI _CONST_RETURN wchar_t * __cdecl MSVCRT$wcschr( const wchar_t * _Str, wchar_t _Ch );

WINBASEAPI wchar_t * __cdecl MSVCRT$wcsrchr( const wchar_t * _Str, wchar_t _Ch );

WINBASEAPI wchar_t * __cdecl MSVCRT$wcsrchr( const wchar_t * _Str, wchar_t _Ch );

WINBASEAPI unsigned long
__cdecl MSVCRT$wcstoul( const wchar_t * __restrict__ _Str, wchar_t ** __restrict__ _EndPtr, int _Radix );

DECLSPEC_IMPORT char * __cdecl MSVCRT$strcat( char * __restrict__ _Dest, const char * __restrict__ _Source );

WINBASEAPI size_t __cdecl MSVCRT$strnlen( const char * _Str, size_t _MaxCount );

WINBASEAPI size_t __cdecl MSVCRT$strlen( const char * _Str );

DECLSPEC_IMPORT int __cdecl MSVCRT$strcmp( const char * _Str1, const char * _Str2 );

DECLSPEC_IMPORT int __cdecl MSVCRT$_stricmp( const char * string1, const char * string2 );

WINBASEAPI int __cdecl MSVCRT$strncmp( const char * _Str1, const char * _Str2, size_t _MaxCount );

DECLSPEC_IMPORT char * __cdecl MSVCRT$strcpy( char * __restrict__ __dst, const char * __restrict__ __src );

DECLSPEC_IMPORT PCHAR __cdecl MSVCRT$strstr( const char * haystack, const char * needle );

DECLSPEC_IMPORT PCHAR __cdecl MSVCRT$strchr( const char * haystack, int needle );

DECLSPEC_IMPORT char * __cdecl MSVCRT$strtok( char * __restrict__ _Str, const char * __restrict__ _Delim );

_CRTIMP char * __cdecl MSVCRT$strtok_s( char * _Str, const char * _Delim, char ** _Context );

WINBASEAPI unsigned long
__cdecl MSVCRT$strtoul( const char * __restrict__ _Str, char ** __restrict__ _EndPtr, int _Radix );

WINBASEAPI size_t
__cdecl MSVCRT$strftime( char * _DstBuf, size_t _SizeInBytes, const char * _Format, const struct tm * _Tm );

WINBASEAPI struct tm * __cdecl MSVCRT$gmtime( const time_t * _Time );

WINBASEAPI wchar_t *
__cdecl MSVCRT$wcsncat( wchar_t * __restrict__ _Dest, const wchar_t * __restrict__ _Source, size_t _Count );

//DNSAPI
DECLSPEC_IMPORT DNS_STATUS WINAPI DNSAPI$DnsQuery_A( PCSTR, WORD, DWORD, PIP4_ARRAY, PDNS_RECORD *, PVOID * );

DECLSPEC_IMPORT VOID WINAPI DNSAPI$DnsFree( PVOID pData, DNS_FREE_TYPE FreeType );

//WSOCK32
DECLSPEC_IMPORT unsigned long __stdcall WSOCK32$inet_addr( const char * cp );

//NETAPI32
DECLSPEC_IMPORT DWORD WINAPI NETAPI32$DsGetDcNameA( LPVOID, LPVOID, LPVOID, LPVOID, ULONG, LPVOID );

WINBASEAPI DWORD WINAPI NETAPI32$NetUserGetInfo( LPCWSTR servername, LPCWSTR username, DWORD level, LPBYTE * bufptr );

WINBASEAPI DWORD WINAPI NETAPI32$NetUserModalsGet( LPCWSTR servername, DWORD level, LPBYTE * bufptr );

WINBASEAPI DWORD WINAPI NETAPI32$NetServerEnum(
	LMCSTR servername, DWORD level, LPBYTE * bufptr, DWORD prefmaxlen, LPDWORD entriesread, LPDWORD totalentries,
	DWORD servertype, LMCSTR domain, LPDWORD resume_handle
);

WINBASEAPI DWORD WINAPI NETAPI32$NetUserGetGroups(
	LPCWSTR servername, LPCWSTR username, DWORD level, LPBYTE * bufptr, DWORD prefmaxlen, LPDWORD entriesread,
	LPDWORD totalentries
);

WINBASEAPI DWORD WINAPI NETAPI32$NetUserGetLocalGroups(
	LPCWSTR servername, LPCWSTR username, DWORD level, DWORD flags, LPBYTE * bufptr, DWORD prefmaxlen,
	LPDWORD entriesread, LPDWORD totalentries
);

WINBASEAPI DWORD WINAPI NETAPI32$NetApiBufferFree( LPVOID Buffer );

WINBASEAPI DWORD WINAPI NETAPI32$NetGetAnyDCName( LPCWSTR servername, LPCWSTR domainname, LPBYTE * bufptr );

WINBASEAPI DWORD WINAPI NETAPI32$NetUserEnum(
	LPCWSTR servername, DWORD level, DWORD filter, LPBYTE * bufptr, DWORD prefmaxlen, LPDWORD entriesread,
	LPDWORD totalentries, LPDWORD resume_handle
);

WINBASEAPI DWORD WINAPI NETAPI32$NetGroupGetUsers(
	LPCWSTR servername, LPCWSTR groupname, DWORD level, LPBYTE * bufptr, DWORD prefmaxlen, LPDWORD entriesread,
	LPDWORD totalentries, PDWORD_PTR ResumeHandle
);

WINBASEAPI DWORD WINAPI NETAPI32$NetQueryDisplayInformation(
	LPCWSTR ServerName, DWORD Level, DWORD Index, DWORD EntriesRequested, DWORD PreferredMaximumLength,
	LPDWORD ReturnedEntryCount, PVOID * SortedBuffer
);

WINBASEAPI DWORD WINAPI NETAPI32$NetLocalGroupEnum(
	LPCWSTR servername, DWORD level, LPBYTE * bufptr, DWORD prefmaxlen, LPDWORD entriesread, LPDWORD totalentries,
	PDWORD_PTR resumehandle
);

WINBASEAPI DWORD WINAPI NETAPI32$NetLocalGroupGetMembers(
	LPCWSTR servername, LPCWSTR localgroupname, DWORD level, LPBYTE * bufptr, DWORD prefmaxlen, LPDWORD entriesread,
	LPDWORD totalentries, PDWORD_PTR resumehandle
);

WINBASEAPI DWORD
WINAPI NETAPI32$NetUserSetInfo( LPCWSTR servername, LPCWSTR username, DWORD level, LPBYTE buf, LPDWORD parm_err );

WINBASEAPI DWORD WINAPI NETAPI32$NetShareEnum(
	LMSTR servername, DWORD level, LPBYTE * bufptr, DWORD prefmaxlen, LPDWORD entriesread, LPDWORD totalentries,
	LPDWORD resume_handle
);

WINBASEAPI DWORD WINAPI NETAPI32$NetApiBufferFree( LPVOID Buffer );

WINBASEAPI DWORD WINAPI NETAPI32$NetSessionEnum(
	LPCWSTR servername, LPCWSTR UncClientName, LPCWSTR username, DWORD level, LPBYTE * bufptr, DWORD prefmaxlen,
	LPDWORD entriesread, LPDWORD totalentries, LPDWORD resumehandle
);

WINBASEAPI DWORD WINAPI NETAPI32$NetWkstaUserEnum(
	LMSTR servername, DWORD level, LPBYTE * bufptr, DWORD prefmaxlen, LPDWORD entriesread, LPDWORD totalentries,
	LPDWORD resumehandle
);

WINBASEAPI DWORD WINAPI NETAPI32$NetWkstaGetInfo( LMSTR servername, DWORD level, LPBYTE * bufptr );

WINBASEAPI DWORD
WINAPI NETAPI32$NetStatisticsGet( LMSTR server, LMSTR service, DWORD level, DWORD options, LPBYTE * bufptr );

WINBASEAPI DWORD WINAPI NETAPI32$NetRemoteTOD( LPCWSTR UncServerName, LPBYTE * BufferPtr );

//mpr
WINBASEAPI DWORD
WINAPI MPR$WNetOpenEnumW( DWORD dwScope, DWORD dwType, DWORD dwUsage, LPNETRESOURCEW lpNetResource, LPHANDLE lphEnum );

WINBASEAPI DWORD WINAPI MPR$WNetEnumResourceW( HANDLE hEnum, LPDWORD lpcCount, LPVOID lpBuffer, LPDWORD lpBufferSize );

WINBASEAPI DWORD WINAPI MPR$WNetCloseEnum( HANDLE hEnum );

WINBASEAPI DWORD WINAPI MPR$WNetGetNetworkInformationW( LPCWSTR lpProvider, LPNETINFOSTRUCT lpNetInfoStruct );

WINBASEAPI DWORD WINAPI MPR$WNetGetConnectionW( LPCWSTR lpLocalName, LPWSTR lpRemoteName, LPDWORD lpnLength );

WINBASEAPI DWORD WINAPI MPR$WNetGetResourceInformationW(
	LPNETRESOURCEW lpNetResource, LPVOID lpBuffer, LPDWORD lpcbBuffer, LPWSTR * lplpSystem
);

WINBASEAPI DWORD WINAPI MPR$WNetGetUserW( LPCWSTR lpName, LPWSTR lpUserName, LPDWORD lpnLength );

WINBASEAPI DWORD
WINAPI MPR$WNetAddConnection2W( LPNETRESOURCEW lpNetResource, LPCWSTR lpPassword, LPCWSTR lpUserName, DWORD dwFlags );

WINBASEAPI DWORD WINAPI MPR$WNetCancelConnection2W( LPCWSTR lpName, DWORD dwFlags, BOOL fForce );

//user32
WINUSERAPI int WINAPI USER32$EnumDesktopWindows( HDESK hDesktop, WNDENUMPROC lpfn, LPARAM lParam );

WINUSERAPI int WINAPI USER32$IsWindowVisible( HWND hWnd );

WINUSERAPI int WINAPI USER32$GetWindowTextA( HWND hWnd, LPSTR lpString, int nMaxCount );

WINUSERAPI int WINAPI USER32$GetClassNameA( HWND hWnd, LPSTR lpClassName, int nMaxCount );

WINUSERAPI LPWSTR WINAPI USER32$CharPrevW( LPCWSTR lpszStart, LPCWSTR lpszCurrent );

WINUSERAPI HWND
WINAPI USER32$FindWindowExA( HWND hWndParent, HWND hWndChildAfter, LPCSTR lpszClass, LPCSTR lpszWindow );

WINUSERAPI LRESULT WINAPI USER32$SendMessageA( HWND hwnd, UINT Msg, WPARAM wParam, LPARAM lParam );

WINUSERAPI int WINAPI USER32$GetWindowTextA( HWND hWnd, LPSTR lpString, int nMaxCount );

WINUSERAPI int WINAPI USER32$GetClassNameA( HWND hWnd, LPTSTR lpClassName, int nMaxCount );

WINUSERAPI BOOL WINAPI USER32$EnumChildWindows( HWND hWndParent, WNDENUMPROC lpEnumFunc, LPARAM lParam );

//secur32
WINBASEAPI BOOLEAN WINAPI SECUR32$GetUserNameExA( int NameFormat, LPSTR lpNameBuffer, PULONG nSize );

//shlwapi
WINBASEAPI LPSTR WINAPI SHLWAPI$StrStrIA( LPCSTR lpFirst, LPCSTR lpSrch );

//advapi32
WINADVAPI WINBOOL WINAPI ADVAPI32$CreateWellKnownSid(
	WELL_KNOWN_SID_TYPE WellKnownSidType,
	PSID DomainSid,
	PSID pSid,
	DWORD * cbSid
);

WINADVAPI WINBOOL WINAPI ADVAPI32$OpenProcessToken( HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle );

WINADVAPI WINBOOL WINAPI ADVAPI32$GetTokenInformation(
	HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, LPVOID TokenInformation,
	DWORD TokenInformationLength, PDWORD ReturnLength
);

WINADVAPI WINBOOL WINAPI ADVAPI32$ConvertSidToStringSidA( PSID Sid, LPSTR * StringSid );

WINADVAPI WINBOOL WINAPI ADVAPI32$ConvertStringSecurityDescriptorToSecurityDescriptorW(
	LPCWSTR StringSecurityDescriptor, DWORD StringSDRevision, PSECURITY_DESCRIPTOR * SecurityDescriptor,
	PULONG SecurityDescriptorSize
);

WINADVAPI WINBOOL WINAPI ADVAPI32$LookupAccountSidA(
	LPCSTR lpSystemName, PSID Sid, LPSTR Name, LPDWORD cchName, LPSTR ReferencedDomainName,
	LPDWORD cchReferencedDomainName, PSID_NAME_USE peUse
);

WINADVAPI WINBOOL WINAPI ADVAPI32$LookupAccountSidW(
	LPCWSTR lpSystemName, PSID Sid, LPWSTR Name, LPDWORD cchName, LPWSTR ReferencedDomainName,
	LPDWORD cchReferencedDomainName, PSID_NAME_USE peUse
);

WINADVAPI WINBOOL
WINAPI ADVAPI32$LookupPrivilegeNameA( LPCSTR lpSystemName, PLUID lpLuid, LPSTR lpName, LPDWORD cchName );

WINADVAPI WINBOOL WINAPI ADVAPI32$LookupPrivilegeDisplayNameA(
	LPCSTR lpSystemName, LPCSTR lpName, LPSTR lpDisplayName, LPDWORD cchDisplayName, LPDWORD lpLanguageId
);

WINADVAPI SC_HANDLE
WINAPI ADVAPI32$OpenSCManagerA( LPCSTR lpMachineName, LPCSTR lpDatabaseName, DWORD dwDesiredAccess );

WINADVAPI SC_HANDLE WINAPI ADVAPI32$OpenServiceA( SC_HANDLE hSCManager, LPCSTR lpServiceName, DWORD dwDesiredAccess );

WINADVAPI WINBOOL WINAPI ADVAPI32$QueryServiceStatus( SC_HANDLE hService, LPSERVICE_STATUS lpServiceStatus );

WINADVAPI WINBOOL WINAPI ADVAPI32$QueryServiceConfigA(
	SC_HANDLE hService, LPQUERY_SERVICE_CONFIGA lpServiceConfig, DWORD cbBufSize, LPDWORD pcbBytesNeeded
);

WINADVAPI WINBOOL WINAPI ADVAPI32$CloseServiceHandle( SC_HANDLE hSCObject );

WINADVAPI WINBOOL WINAPI ADVAPI32$EnumServicesStatusExA(
	SC_HANDLE hSCManager, SC_ENUM_TYPE InfoLevel, DWORD dwServiceType, DWORD dwServiceState, LPBYTE lpServices,
	DWORD cbBufSize, LPDWORD pcbBytesNeeded, LPDWORD lpServicesReturned, LPDWORD lpResumeHandle, LPCSTR pszGroupName
);

WINADVAPI WINBOOL WINAPI ADVAPI32$QueryServiceStatusEx(
	SC_HANDLE hService, SC_STATUS_TYPE InfoLevel, LPBYTE lpBuffer, DWORD cbBufSize, LPDWORD pcbBytesNeeded
);

WINADVAPI WINBOOL WINAPI ADVAPI32$QueryServiceConfig2A(
	SC_HANDLE hService, DWORD dwInfoLevel, LPBYTE lpBuffer, DWORD cbBufSize, LPDWORD pcbBytesNeeded
);

WINADVAPI WINBOOL WINAPI ADVAPI32$ChangeServiceConfig2A( SC_HANDLE hService, DWORD dwInfoLevel, LPVOID lpInfo );

WINADVAPI WINBOOL WINAPI ADVAPI32$ChangeServiceConfigA(
	SC_HANDLE hService, DWORD dwServiceType, DWORD dwStartType, DWORD dwErrorControl, LPCSTR lpBinaryPathName,
	LPCSTR lpLoadOrderGroup, LPDWORD lpdwTagId, LPCSTR lpDependencies, LPCSTR lpServiceStartName, LPCSTR lpPassword,
	LPCSTR lpDisplayName
);

WINADVAPI SC_HANDLE WINAPI ADVAPI32$CreateServiceA(
	SC_HANDLE hSCManager, LPCSTR lpServiceName, LPCSTR lpDisplayName, DWORD dwDesiredAccess, DWORD dwServiceType,
	DWORD dwStartType, DWORD dwErrorControl, LPCSTR lpBinaryPathName, LPCSTR lpLoadOrderGroup, LPDWORD lpdwTagId,
	LPCSTR lpDependencies, LPCSTR lpServiceStartName, LPCSTR lpPassword
);

WINADVAPI WINBOOL WINAPI ADVAPI32$DeleteService( SC_HANDLE hService );

WINADVAPI LONG
WINAPI ADVAPI32$RegOpenKeyExW( HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult );

WINADVAPI WINBOOL WINAPI ADVAPI32$EnumServicesStatusExW(
	SC_HANDLE hSCManager, SC_ENUM_TYPE InfoLevel, DWORD dwServiceType, DWORD dwServiceState, LPBYTE lpServices,
	DWORD cbBufSize, LPDWORD pcbBytesNeeded, LPDWORD lpServicesReturned, LPDWORD lpResumeHandle, LPCWSTR pszGroupName
);

WINADVAPI LONG WINAPI ADVAPI32$RegCreateKeyA( HKEY hKey, LPCSTR lpSubKey, PHKEY phkResult );

WINADVAPI LONG WINAPI ADVAPI32$RegSetValueExA(
	HKEY hKey, LPCSTR lpValueName, DWORD Reserved, DWORD dwType, CONST BYTE * lpData, DWORD cbData
);

WINADVAPI LONG
WINAPI ADVAPI32$RegOpenKeyExA( HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult );

WINADVAPI LONG WINAPI ADVAPI32$RegConnectRegistryA( LPCSTR lpMachineName, HKEY hKey, PHKEY phkResult );

WINADVAPI LONG WINAPI ADVAPI32$RegCloseKey( HKEY hKey );

WINADVAPI LONG WINAPI ADVAPI32$RegOpenKeyA( HKEY hKey, LPCSTR lpSubKey, PHKEY phkResult );

WINADVAPI LONG WINAPI ADVAPI32$RegCreateKeyExA(
	HKEY hKey, LPCSTR lpSubKey, DWORD Reserved, LPSTR lpClass, DWORD dwOptions, REGSAM samDesired,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult, LPDWORD lpdwDisposition
);

WINADVAPI LONG WINAPI ADVAPI32$RegDeleteKeyExA( HKEY hKey, LPCSTR lpSubKey, REGSAM samDesired, DWORD Reserved );

WINADVAPI LONG WINAPI ADVAPI32$RegDeleteKeyValueA( HKEY hKey, LPCSTR lpSubKey, LPCSTR lpValueName );

WINADVAPI LONG WINAPI ADVAPI32$RegQueryValueExA(
	HKEY hKey, LPCSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData
);

WINADVAPI LONG WINAPI ADVAPI32$RegQueryInfoKeyA(
	HKEY hKey, LPSTR lpClass, LPDWORD lpcchClass, LPDWORD lpReserved, LPDWORD lpcSubKeys, LPDWORD lpcbMaxSubKeyLen,
	LPDWORD lpcbMaxClassLen, LPDWORD lpcValues, LPDWORD lpcbMaxValueNameLen, LPDWORD lpcbMaxValueLen,
	LPDWORD lpcbSecurityDescriptor, PFILETIME lpftLastWriteTime
);

WINADVAPI LONG WINAPI ADVAPI32$RegEnumValueA(
	HKEY hKey, DWORD dwIndex, LPSTR lpValueName, LPDWORD lpcchValueName, LPDWORD lpReserved, LPDWORD lpType,
	LPBYTE lpData, LPDWORD lpcbData
);

WINADVAPI LONG WINAPI ADVAPI32$RegEnumKeyExA(
	HKEY hKey, DWORD dwIndex, LPSTR lpName, LPDWORD lpcchName, LPDWORD lpReserved, LPSTR lpClass, LPDWORD lpcchClass,
	PFILETIME lpftLastWriteTime
);

WINADVAPI LONG WINAPI ADVAPI32$RegDeleteValueA( HKEY hKey, LPCSTR lpValueName );

WINADVAPI LONG WINAPI ADVAPI32$RegQueryValueExW(
	HKEY hKey, LPCWSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData
);

WINADVAPI LONG
WINAPI ADVAPI32$RegSaveKeyExA( HKEY hKey, LPCSTR lpFile, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD Flags );

WINADVAPI WINBOOL WINAPI ADVAPI32$GetFileSecurityW(
	LPCWSTR lpFileName, SECURITY_INFORMATION RequestedInformation, PSECURITY_DESCRIPTOR pSecurityDescriptor,
	DWORD nLength, LPDWORD lpnLengthNeeded
);

WINADVAPI WINBOOL WINAPI ADVAPI32$GetSecurityDescriptorOwner(
	PSECURITY_DESCRIPTOR pSecurityDescriptor, PSID * pOwner, LPBOOL lpbOwnerDefaulted
);

WINADVAPI WINBOOL WINAPI ADVAPI32$GetSecurityDescriptorDacl(
	PSECURITY_DESCRIPTOR pSecurityDescriptor, LPBOOL lpbDaclPresent, PACL * pDacl, LPBOOL lpbDaclDefaulted
);

WINADVAPI WINBOOL WINAPI ADVAPI32$GetAclInformation(
	PACL pAcl, LPVOID pAclInformation, DWORD nAclInformationLength, ACL_INFORMATION_CLASS dwAclInformationClass
);

WINADVAPI WINBOOL WINAPI ADVAPI32$GetAce( PACL pAcl, DWORD dwAceIndex, LPVOID * pAce );

WINADVAPI WINBOOL WINAPI ADVAPI32$LookupAccountSidW(
	LPCWSTR lpSystemName, PSID Sid, LPWSTR Name, LPDWORD cchName, LPWSTR ReferencedDomainName,
	LPDWORD cchReferencedDomainName, PSID_NAME_USE peUse
);

WINADVAPI WINBOOL WINAPI ADVAPI32$ConvertSidToStringSidW( PSID Sid, LPWSTR * StringSid );

WINADVAPI VOID WINAPI ADVAPI32$MapGenericMask( PDWORD AccessMask, PGENERIC_MAPPING GenericMapping );

WINADVAPI WINBOOL WINAPI ADVAPI32$OpenProcessToken( HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle );

WINADVAPI WINBOOL WINAPI ADVAPI32$GetTokenInformation(
	HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, LPVOID TokenInformation,
	DWORD TokenInformationLength, PDWORD ReturnLength
);

WINADVAPI WINBOOL
WINAPI ADVAPI32$InitializeSecurityDescriptor( PSECURITY_DESCRIPTOR pSecurityDescriptor, DWORD dwRevision );

WINADVAPI WINBOOL WINAPI ADVAPI32$SetSecurityDescriptorDacl(
	PSECURITY_DESCRIPTOR pSecurityDescriptor, WINBOOL bDaclPresent, PACL pDacl, WINBOOL bDaclDefaulted
);

WINADVAPI WINBOOL WINAPI ADVAPI32$ConvertSecurityDescriptorToStringSecurityDescriptorW(
	PSECURITY_DESCRIPTOR SecurityDescriptor, DWORD RequestedStringSDRevision, SECURITY_INFORMATION SecurityInformation,
	LPWSTR * StringSecurityDescriptor, PULONG StringSecurityDescriptorLen
);

WINADVAPI WINBOOL
WINAPI ADVAPI32$StartServiceA( SC_HANDLE hService, DWORD dwNumServiceArgs, LPCSTR * lpServiceArgVectors );

WINADVAPI WINBOOL
WINAPI ADVAPI32$ControlService( SC_HANDLE hService, DWORD dwControl, LPSERVICE_STATUS lpServiceStatus );

WINADVAPI WINBOOL WINAPI ADVAPI32$EnumDependentServicesA(
	SC_HANDLE hService, DWORD dwServiceState, LPENUM_SERVICE_STATUSA lpServices, DWORD cbBufSize,
	LPDWORD pcbBytesNeeded, LPDWORD lpServicesReturned
);

//IMAGEHLP
WINBASEAPI WINBOOL IMAGEAPIIMAGEHLP$ImageEnumerateCertificates(
	HANDLE FileHandle, WORD TypeFilter, PDWORD CertificateCount, PDWORD Indices, DWORD IndexCount
);

WINBASEAPI WINBOOL IMAGEAPI
IMAGEHLP$ImageGetCertificateHeader( HANDLE FileHandle, DWORD CertificateIndex, LPWIN_CERTIFICATE Certificateheader );

WINBASEAPI WINBOOL IMAGEAPIIMAGEHLP$ImageGetCertificateData(
	HANDLE FileHandle, DWORD CertificateIndex, LPWIN_CERTIFICATE Certificate, PDWORD RequiredLength
);

//crypt32
WINIMPM WINBOOL WINAPI CRYPT32$CryptVerifyMessageSignature(
	PCRYPT_VERIFY_MESSAGE_PARA pVerifyPara, DWORD dwSignerIndex, const BYTE * pbSignedBlob, DWORD cbSignedBlob,
	BYTE * pbDecoded, DWORD * pcbDecoded, PCCERT_CONTEXT * ppSignerCert
);

WINIMPM DWORD WINAPI CRYPT32$CertGetNameStringW(
	PCCERT_CONTEXT pCertContext, DWORD dwType, DWORD dwFlags, void * pvTypePara, LPWSTR pszNameString,
	DWORD cchNameString
);

WINIMPM PCCERT_CONTEXT WINAPI CRYPT32$CertCreateCertificateContext(
	DWORD dwCertEncodingType, const BYTE * pbCertEncoded, DWORD cbCertEncoded
);

WINIMPM WINBOOL WINAPI CRYPT32$CertFreeCertificateContext( PCCERT_CONTEXT pCertContext );

WINIMPM WINBOOL WINAPI CRYPT32$CertGetCertificateContextProperty(
	PCCERT_CONTEXT pCertContext, DWORD dwPropId, void * pvData, DWORD * pcbData
);

WINIMPM WINBOOL WINAPI CRYPT32$CertGetCertificateChain(
	HCERTCHAINENGINE hChainEngine, PCCERT_CONTEXT pCertContext, LPFILETIME pTime, HCERTSTORE hAdditionalStore,
	PCERT_CHAIN_PARA pChainPara, DWORD dwFlags, LPVOID pvReserved, PCCERT_CHAIN_CONTEXT * ppChainContext
);

WINIMPM VOID WINAPI CRYPT32$CertFreeCertificateChain( PCCERT_CHAIN_CONTEXT pChainContext );

WINIMPM PCCRYPT_OID_INFO WINAPI CRYPT32$CryptFindOIDInfo( DWORD dwKeyType, void * pvKey, DWORD dwGroupId );

//WS2_32
// defining this here to avoid including ws2tcpip.h which results in include order warnings when bofs include windows.h before bofdefs.h
typedef struct addrinfo {
	int    ai_flags;
	int    ai_family;
	int    ai_socktype;
	int    ai_protocol;
	size_t ai_addrlen;
	char            * ai_canonname;
	struct sockaddr * ai_addr;
	struct addrinfo * ai_next;
} ADDRINFOA, * PADDRINFOA;

//WS2_32
DECLSPEC_IMPORT int __stdcall WS2_32$connect( SOCKET sock, const struct sockaddr * name, int namelen );

DECLSPEC_IMPORT int __stdcall WS2_32$closesocket( SOCKET sock );

DECLSPEC_IMPORT void __stdcall WS2_32$freeaddrinfo( struct addrinfo * ai );

DECLSPEC_IMPORT int
__stdcall WS2_32$getaddrinfo( char * host, char * port, const struct addrinfo * hints, struct addrinfo ** result );

DECLSPEC_IMPORT u_long __stdcall WS2_32$htonl( u_long hostlong );

DECLSPEC_IMPORT u_short __stdcall WS2_32$htons( u_short hostshort );

DECLSPEC_IMPORT char * __stdcall WS2_32$inet_ntoa( struct in_addr in );

DECLSPEC_IMPORT int __stdcall WS2_32$ioctlsocket( SOCKET sock, long cmd, u_long * arg );

DECLSPEC_IMPORT int __stdcall WS2_32$select(
	int nfds, fd_set * readfds, fd_set * writefds, fd_set * exceptfds, const struct timeval * timeout
);

DECLSPEC_IMPORT unsigned int __stdcall WS2_32$socket( int af, int type, int protocol );

DECLSPEC_IMPORT int __stdcall WS2_32$__WSAFDIsSet( SOCKET sock, struct fd_set * fdset );

DECLSPEC_IMPORT int __stdcall WS2_32$WSAGetLastError();

DECLSPEC_IMPORT LPCWSTR WINAPI WS2_32$InetNtopW( INT Family, LPCVOID pAddr, LPWSTR pStringBuf, size_t StringBufSIze );

DECLSPEC_IMPORT INT WINAPI WS2_32$inet_pton( INT Family, LPCSTR pStringBuf, PVOID pAddr );

//dnsapi
DECLSPEC_IMPORT VOID WINAPI DNSAPI$DnsFree( PVOID pData, DNS_FREE_TYPE FreeType );

DECLSPEC_IMPORT int WINAPI DNSAPI$DnsGetCacheDataTable( PVOID data );

//OLE32
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoInitializeEx( LPVOID pvReserved, DWORD dwCoInit );

DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoUninitialize( void );

DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoInitializeSecurity(
	PSECURITY_DESCRIPTOR pSecDesc, LONG cAuthSvc, SOLE_AUTHENTICATION_SERVICE * asAuthSvc, void * pReserved1,
	DWORD dwAuthnLevel, DWORD dwImpLevel, void * pAuthList, DWORD dwCapabilities, void * pReserved3
);

DECLSPEC_IMPORT HRESULT
WINAPI OLE32$CoCreateInstance( REFCLSID rclsid, LPUNKNOWN pUnkOuter, DWORD dwClsContext, REFIID riid, LPVOID * ppv );

DECLSPEC_IMPORT HRESULT WINAPI OLE32$CLSIDFromString( LPCOLESTR lpsz, LPCLSID pclsid );

DECLSPEC_IMPORT HRESULT WINAPI OLE32$IIDFromString( LPCOLESTR lpsz, LPIID lpiid );

DECLSPEC_IMPORT int WINAPI OLE32$StringFromGUID2( REFGUID rguid, LPOLESTR lpsz, int cchMax );

DECLSPEC_IMPORT    HRESULT WINAPI OLE32$CoSetProxyBlanket(
	IUnknown * pProxy, DWORD dwAuthnSvc, DWORD dwAuthzSvc, OLECHAR * pServerPrincName, DWORD dwAuthnLevel,
	DWORD dwImpLevel, RPC_AUTH_IDENTITY_HANDLE pAuthInfo, DWORD dwCapabilities
);

DECLSPEC_IMPORT LPVOID WINAPI OLE32$CoTaskMemAlloc( SIZE_T cb );

DECLSPEC_IMPORT void WINAPI OLE32$CoTaskMemFree( LPVOID pv );

//OLEAUT32
DECLSPEC_IMPORT BSTR WINAPI OLEAUT32$SysAllocString( const OLECHAR * );

DECLSPEC_IMPORT INT WINAPI OLEAUT32$SysReAllocString( BSTR *, const OLECHAR * );

DECLSPEC_IMPORT void WINAPI OLEAUT32$SysFreeString( BSTR );

DECLSPEC_IMPORT UINT WINAPI OLEAUT32$SysStringLen( BSTR );

DECLSPEC_IMPORT void WINAPI OLEAUT32$VariantInit( VARIANTARG * pvarg );

DECLSPEC_IMPORT void WINAPI OLEAUT32$VariantClear( VARIANTARG * pvarg );

DECLSPEC_IMPORT HRESULT WINAPI OLEAUT32$SysAddRefString( BSTR );

DECLSPEC_IMPORT HRESULT
WINAPI OLEAUT32$VariantChangeType( VARIANTARG * pvargDest, VARIANTARG * pvarSrc, USHORT wFlags, VARTYPE vt );

DECLSPEC_IMPORT void
WINAPI OLEAUT32$VarFormatDateTime( LPVARIANT pvarIn, int iNamedFormat, ULONG dwFlags, BSTR * pbstrOut );

DECLSPEC_IMPORT void WINAPI OLEAUT32$SafeArrayDestroy( SAFEARRAY * psa );

DECLSPEC_IMPORT HRESULT WINAPI OLEAUT32$SafeArrayLock( SAFEARRAY * psa );

DECLSPEC_IMPORT HRESULT WINAPI OLEAUT32$SafeArrayGetLBound( SAFEARRAY * psa, UINT nDim, LONG * plLbound );

DECLSPEC_IMPORT HRESULT WINAPI OLEAUT32$SafeArrayGetUBound( SAFEARRAY * psa, UINT nDim, LONG * plUbound );

DECLSPEC_IMPORT HRESULT WINAPI OLEAUT32$SafeArrayGetElement( SAFEARRAY * psa, LONG * rgIndices, void * pv );

DECLSPEC_IMPORT UINT WINAPI OLEAUT32$SafeArrayGetElemsize( SAFEARRAY * psa );

DECLSPEC_IMPORT HRESULT WINAPI OLEAUT32$SafeArrayAccessData( SAFEARRAY * psa, void HUGEP ** ppvData );

DECLSPEC_IMPORT HRESULT WINAPI OLEAUT32$SafeArrayUnaccessData( SAFEARRAY * psa );

//CERTCLI
DECLSPEC_IMPORT HRESULT WINAPI CERTCLI$CAEnumFirstCA( IN LPCWSTR wszScope, IN DWORD dwFlags, OUT LPVOID * phCAInfo );

DECLSPEC_IMPORT HRESULT WINAPI CERTCLI$CAEnumNextCA( IN LPVOID hPrevCA, OUT LPVOID * phCAInfo );

DECLSPEC_IMPORT HRESULT WINAPI CERTCLI$CACloseCA( IN LPVOID hCA );

DECLSPEC_IMPORT DWORD WINAPI CERTCLI$CACountCAs( IN LPVOID hCAInfo );

DECLSPEC_IMPORT LPCWSTR WINAPI CERTCLI$CAGetDN( IN LPVOID hCAInfo );

DECLSPEC_IMPORT HRESULT
WINAPI CERTCLI$CAGetCAProperty( IN LPVOID hCAInfo, IN LPCWSTR wszPropertyName, OUT PZPWSTR * pawszPropertyValue );

DECLSPEC_IMPORT HRESULT WINAPI CERTCLI$CAFreeCAProperty( IN LPVOID hCAInfo, IN PZPWSTR awszPropertyValue );

DECLSPEC_IMPORT HRESULT WINAPI CERTCLI$CAGetCAFlags( IN LPVOID hCAInfo, OUT DWORD * pdwFlags );

DECLSPEC_IMPORT HRESULT WINAPI CERTCLI$CAGetCACertificate( IN LPVOID hCAInfo, OUT PCCERT_CONTEXT * ppCert );

DECLSPEC_IMPORT HRESULT
WINAPI CERTCLI$CAGetCAExpiration( IN LPVOID hCAInfo, OUT DWORD * pdwExpiration, OUT DWORD * pdwUnits );

DECLSPEC_IMPORT HRESULT WINAPI CERTCLI$CAGetCASecurity( IN LPVOID hCAInfo, OUT PSECURITY_DESCRIPTOR * ppSD );

DECLSPEC_IMPORT HRESULT
WINAPI CERTCLI$CAGetAccessRights( IN LPVOID hCAInfo, IN DWORD dwContext, OUT DWORD * pdwAccessRights );

DECLSPEC_IMPORT HRESULT
WINAPI CERTCLI$CAEnumCertTypesForCA( IN LPVOID hCAInfo, IN DWORD dwFlags, OUT LPVOID * phCertType );

DECLSPEC_IMPORT HRESULT WINAPI CERTCLI$CAEnumCertTypes( IN DWORD dwFlags, OUT LPVOID * phCertType );

DECLSPEC_IMPORT HRESULT WINAPI CERTCLI$CAEnumNextCertType( IN LPVOID hPrevCertType, OUT LPVOID * phCertType );

DECLSPEC_IMPORT DWORD WINAPI CERTCLI$CACountCertTypes( IN LPVOID hCertType );

DECLSPEC_IMPORT HRESULT WINAPI CERTCLI$CACloseCertType( IN LPVOID hCertType );

DECLSPEC_IMPORT HRESULT WINAPI CERTCLI$CAGetCertTypeProperty(
	IN LPVOID hCertType, IN LPCWSTR wszPropertyName, OUT PZPWSTR * pawszPropertyValue
);

DECLSPEC_IMPORT HRESULT
WINAPI CERTCLI$CAGetCertTypePropertyEx( IN LPVOID hCertType, IN LPCWSTR wszPropertyName, OUT LPVOID * pPropertyValue );

DECLSPEC_IMPORT HRESULT WINAPI CERTCLI$CAFreeCertTypeProperty( IN LPVOID hCertType, IN PZPWSTR awszPropertyValue );

DECLSPEC_IMPORT HRESULT WINAPI CERTCLI$CAGetCertTypeExtensionsEx(
	IN LPVOID hCertType, IN DWORD dwFlags, IN LPVOID pParam, OUT PCERT_EXTENSIONS * ppCertExtensions
);

DECLSPEC_IMPORT HRESULT
WINAPI CERTCLI$CAFreeCertTypeExtensions( IN LPVOID hCertType, IN PCERT_EXTENSIONS pCertExtensions );

DECLSPEC_IMPORT HRESULT
WINAPI CERTCLI$CAGetCertTypeFlagsEx( IN LPVOID hCertType, IN DWORD dwOption, OUT DWORD * pdwFlags );

DECLSPEC_IMPORT HRESULT WINAPI CERTCLI$CAGetCertTypeExpiration(
	IN LPVOID hCertType, OUT OPTIONAL FILETIME * pftExpiration, OUT OPTIONAL FILETIME * pftOverlap
);

DECLSPEC_IMPORT HRESULT WINAPI CERTCLI$CACertTypeGetSecurity( IN LPVOID hCertType, OUT PSECURITY_DESCRIPTOR * ppSD );

DECLSPEC_IMPORT HRESULT
WINAPI CERTCLI$CAGetCertTypeAccessRights( IN LPVOID hCertType, IN DWORD dwContext, OUT DWORD * pdwAccessRights );

DECLSPEC_IMPORT HRESULT WINAPI CERTCLI$caTranslateFileTimePeriodToPeriodUnits(
	IN FILETIME const * pftGMT, IN BOOL Flags, OUT DWORD * pcPeriodUnits, OUT LPVOID * prgPeriodUnits
);

//dbghelp
DECLSPEC_IMPORT WINBOOL WINAPI DBGHELP$MiniDumpWriteDump(
	HANDLE hProcess, DWORD ProcessId, HANDLE hFile, MINIDUMP_TYPE DumpType,
	CONST PMINIDUMP_EXCEPTION_INFORMATION ExceptionParam, CONST PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam,
	CONST PMINIDUMP_CALLBACK_INFORMATION CallbackParam
);

//WLDAP32
WINLDAPAPI LDAP * LDAPAPI WLDAP32$ldap_init( PSTR, ULONG );

WINLDAPAPI ULONG LDAPAPI WLDAP32$ldap_bind_s( LDAP * ld, const PSTR dn, const PCHAR cred, ULONG method );

WINLDAPAPI ULONG LDAPAPI WLDAP32$ldap_search_s(
	LDAP * ld, PSTR base, ULONG scope, PSTR filter, PZPSTR attrs, ULONG attrsonly, PLDAPMessage * res
);

WINLDAPAPI ULONG LDAPAPI WLDAP32$ldap_count_entries( LDAP *, LDAPMessage * );

WINLDAPAPI struct berval **
LDAPAPI WLDAP32$ldap_get_values_lenA( LDAP * ExternalHandle, LDAPMessage * Message, const PCHAR attr );

WINLDAPAPI ULONG LDAPAPI WLDAP32$ldap_value_free_len( struct berval ** vals );

WINLDAPAPI ULONG LDAPAPI WLDAP32$ldap_set_optionA( LDAP * ld, int option, const void * invalue );

WINLDAPAPI PLDAPSearch LDAPAPI WLDAP32$ldap_search_init_pageA(
	PLDAP ExternalHandle, const PCHAR DistinguishedName, ULONG ScopeOfSearch, const PCHAR SearchFilter,
	PCHAR AttributeList[], ULONG AttributesOnly, PLDAPControlA * ServerControls, PLDAPControlA * ClientControls,
	ULONG PageTimeLimit, ULONG TotalSizeLimit, PLDAPSortKeyA * SortKeys
);

WINLDAPAPI ULONG LDAPAPI WLDAP32$ldap_get_paged_count(
	PLDAP ExternalHandle, PLDAPSearch SearchBlock, ULONG * TotalCount, PLDAPMessage Results
);

WINLDAPAPI ULONG LDAPAPI WLDAP32$ldap_get_next_page_s(
	PLDAP ExternalHandle, PLDAPSearch SearchHandle, struct l_timeval * timeout, ULONG PageSize, ULONG * TotalCount,
	LDAPMessage ** Results
);

WINLDAPAPI LDAPMessage * LDAPAPI WLDAP32$ldap_first_entry( LDAP * ld, LDAPMessage * res );

WINLDAPAPI LDAPMessage * LDAPAPI WLDAP32$ldap_next_entry( LDAP *, LDAPMessage * );

WINLDAPAPI PCHAR LDAPAPI WLDAP32$ldap_first_attribute( LDAP * ld, LDAPMessage * entry, BerElement ** ptr );

WINLDAPAPI ULONG LDAPAPI WLDAP32$ldap_count_values( PCHAR );

WINLDAPAPI PCHAR * LDAPAPI WLDAP32$ldap_get_values( LDAP * ld, LDAPMessage * entry, const PSTR attr );

WINLDAPAPI ULONG LDAPAPI WLDAP32$ldap_value_free( PCHAR * );

WINLDAPAPI PCHAR LDAPAPI WLDAP32$ldap_next_attribute( LDAP * ld, LDAPMessage * entry, BerElement * ptr );

WINLDAPAPI VOID LDAPAPI WLDAP32$ber_free( BerElement * pBerElement, INT fbuf );

WINLDAPAPI VOID LDAPAPI WLDAP32$ldap_memfree( PCHAR );

WINLDAPAPI ULONG LDAPAPI WLDAP32$ldap_unbind( LDAP * );

WINLDAPAPI ULONG LDAPAPI WLDAP32$ldap_unbind_s( LDAP * );

WINLDAPAPI ULONG LDAPAPI WLDAP32$ldap_msgfree( LDAPMessage * );

//RPCRT4
RPCRTAPI RPC_STATUS RPC_ENTRY RPCRT4$UuidToStringA( UUID * Uuid, RPC_CSTR * StringUuid );

RPCRTAPI RPC_STATUS RPC_ENTRY RPCRT4$RpcStringFreeA( RPC_CSTR * String );

//PSAPI
DECLSPEC_IMPORT WINBOOL WINAPI PSAPI$EnumProcessModulesEx(
	HANDLE hProcess, HMODULE * lphModule, DWORD cb, LPDWORD lpcbNeeded, DWORD dwFilterFlag
);

DECLSPEC_IMPORT DWORD
WINAPI PSAPI$GetModuleFileNameExA( HANDLE hProcess, HMODULE hModule, LPSTR lpFilename, DWORD nSize );

//VERSION
DECLSPEC_IMPORT DWORD WINAPI VERSION$GetFileVersionInfoSizeA( LPCSTR lptstrFilenamea, LPDWORD lpdwHandle );

DECLSPEC_IMPORT WINBOOL
WINAPI VERSION$GetFileVersionInfoA( LPCSTR lptstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData );

DECLSPEC_IMPORT WINBOOL
WINAPI VERSION$VerQueryValueA( LPCVOID pBlock, LPCSTR lpSubBlock, LPVOID * lplpBuffer, PUINT puLen );

#endif //BOFDEFS_H