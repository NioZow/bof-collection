#include <Defs.h>

int StrCmp( char *str1, char *str2 ) {
    do {
        if ( *str1 != *str2 ) return 0;
    } while ( *( ++str1 ) && *( ++str2 ) );

    if ( ! *str1 ) str2++;

    return *str1 == *str2;
}

int StrnCmp( char *str1, char *str2, int cnt ) {
    int i = 0;

    do {
        if ( *str1 != *str2 ) return 1;
    } while ( ++i < cnt && *( ++str1 ) && *( ++str2 ) );

    if ( ! *str1 ) str2++;

    return ( i == cnt ) ? 0 : *str1 != *str2;
}

char *Strchr( char *str, char ch ) {
    do {
        if ( *str == ch ) return str;
    } while ( *( ++str ) );

    return 0;
}

int StrLen( char *str ) {
    int cnt = 0;

    do {
        cnt++;
    } while ( *( ++str ) );

    return cnt;
}

SIZE_T CharStringToWCharString(
    OUT PWCHAR Destination,
    IN PCHAR   Source,
    IN SIZE_T  MaximumAllowed
) {
    SIZE_T Length = MaximumAllowed;

    while ( --Length >= 0 ) {
        if ( ! ( *Destination++ = *Source++ ) ) return MaximumAllowed - Length - 1;
    }

    return MaximumAllowed - Length;
}

VOID CharStringToUnicodeString(
    IN PCHAR            String,
    IN ULONG            Length,
    OUT PUNICODE_STRING UnicodeString
) {
    // stop if invalid parameters
    if ( ! String || ! Length || ! UnicodeString ) {
        return;
    }

    UnicodeString->MaximumLength = Length * sizeof( WCHAR );
    UnicodeString->Length        = UnicodeString->MaximumLength - sizeof( WCHAR );
    UnicodeString->Buffer        = NTDLL$RtlAllocateHeap(
        NtCurrentPeb()->ProcessHeap, 0, UnicodeString->MaximumLength
    );
    CharStringToWCharString( UnicodeString->Buffer, String, Length );
}

/*

VOID _RtlInitUnicodeString(
    _Out_ PUNICODE_STRING DestinationString,
    _In_opt_z_ PCWSTR     SourceString
) {
    if ( SourceString )
        DestinationString->MaximumLength = ( DestinationString->Length = ( USHORT ) (
                                                 wcslen( SourceString ) * sizeof( WCHAR ) ) ) + sizeof( UNICODE_NULL );
    else
        DestinationString->MaximumLength = DestinationString->Length = 0;

    DestinationString->Buffer = ( PWCH ) SourceString;
}

 */