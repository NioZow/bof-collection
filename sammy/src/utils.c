// utils functions
#include <windows.h>
#include <Native.h>
#include <Defs.h>

VOID MemCpy(
	_Out_ PVOID Dst,
	_In_ PVOID Src,
	_In_ ULONG Size
) {
	for ( ULONG i = 0 ; i < Size ; i ++ ) {
		C_DEF08( ( C_PTR( Dst ) + i ) ) = C_DEF08( ( C_PTR( Src ) + i ) );
	}
}

int StrCmp( char * str1, char * str2 ) {

	do {
		if ( * str1 != * str2 ) return FALSE;
	} while ( * ( ++ str1 ) && * ( ++ str2 ) );

	if ( ! * str1 ) str2 ++;

	return * str1 == * str2;
}

int StrnCmp( char * str1, char * str2, int cnt ) {
	int i = 0;

	do {
		if ( * str1 != * str2 ) return 1;
	} while ( ++ i < cnt && * ( ++ str1 ) && * ( ++ str2 ) );

	if ( ! * str1 ) str2 ++;

	return ( i == cnt ) ? 0 : * str1 != * str2;
}

/*
int StrLen( char * str ) {
	int cnt = 0;

	do {
		cnt ++;
	} while ( * ( ++ str ) );

	return cnt;
}
 */

SIZE_T CharStringToWCharString(
	_Out_ PWCHAR Destination,
	_In_  PCHAR Source,
	_In_  SIZE_T MaximumAllowed
) {
	SIZE_T Length = MaximumAllowed;

	while ( -- Length >= 0 ) {
		if ( ! ( * Destination ++ = * Source ++ ) ) return MaximumAllowed - Length - 1;
	}

	return MaximumAllowed - Length;
}


VOID CharStringToUnicodeString(
	_In_ PCHAR String,
	_In_ ULONG Length,
	_Out_ PUNICODE_STRING UnicodeString
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