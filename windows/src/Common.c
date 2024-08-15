#include <Common.h>

PVOID MmAlloc(
    ULONG size
) {
    return NTDLL$RtlAllocateHeap( NtCurrentHeap(), HEAP_ZERO_MEMORY, size );
}

PVOID MmFree(
    PVOID ptr
) {
    return NTDLL$RtlFreeHeap( NtCurrentHeap(), 0, ptr );
}

PVOID MmReAlloc(
    PVOID ptr,
    ULONG size
) {
    return NTDLL$RtlReAllocateHeap( NtCurrentHeap(), HEAP_ZERO_MEMORY, ptr, size );
}

BOOL StringCompareW(
    IN PWSTR str1,
    IN PWSTR str2
) {
    do {
        if ( *str1 != *str2 ) return FALSE;
    } while ( *( ++str1 ) && *( ++str2 ) );

    if ( ! *str1 ) ++str2;

    return *str1 == *str2;
}

BOOL StringCompareA(
    IN PSTR str1,
    IN PSTR str2
) {
    do {
        if ( *str1 != *str2 ) return FALSE;
    } while ( *( ++str1 ) && *( ++str2 ) );

    if ( ! *str1 ) ++str2;

    return *str1 == *str2;
}
