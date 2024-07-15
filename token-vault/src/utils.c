#include <windows.h>
#include <Defs.h>

/*!
 * @brief
 *	convert a wide string to uppercase
 *
 * @param out
 *	out buffer
 *
 * @param sz
 *	size of the string (in/out)
 *
 * @param in
 *	size of the input string
 */
VOID StringToUpperW(
	OUT PWSTR out,
	IN INT    sz,
	IN PWSTR  in
) {
	for ( int i = 0 ; i < sz ; i++ ) {
		if ( in[ i ] >= 97 && in[ i ] <= 122 ) {
			out[ i ] = in[ i ] - 32;
		} else {
			out[ i ] = in[ i ];
		}
	}
}

/*!
 * @brief
 *	convert an ansi string to uppercase
 *
 * @param out
 *	out buffer
 *
 * @param sz
 *	size of the string (in/out)
 *
 * @param in
 *	size of the input string
 */
VOID StringToUpperA(
	OUT PCHAR out,
	IN INT    sz,
	IN PCHAR  in
) {
	for ( int i = 0 ; i < sz ; i++ ) {
		if ( in[ i ] >= 97 && in[ i ] <= 122 ) {
			out[ i ] = in[ i ] - 32;
		} else {
			out[ i ] = in[ i ];
		}
	}
}

void MemCopy( unsigned char *out, unsigned char *in, int size ) {
	for ( int i = 0 ; i < size ; i++ ) {
		out[ i ] = in[ i ];
	}
}

void MemSet( unsigned char *out, unsigned char in, int size ) {
	for ( int i = 0 ; i < size ; i++ ) {
		out[ i ] = in;
	}
}

int StringCompareA( char *str1, char *str2 ) {
	do {
		if ( *str1 != *str2 ) return FALSE;
	} while ( *( ++str1 ) && *( ++str2 ) );

	if ( ! *str1 ) str2++;

	return *str1 == *str2;
}

int StringNCompareA( char *str1, char *str2, int cnt ) {
	int i = 0;

	do {
		if ( *str1 != *str2 ) return 1;
	} while ( ++i < cnt && *( ++str1 ) && *( ++str2 ) );

	if ( ! *str1 ) str2++;

	return ( i == cnt ) ? 0 : *str1 != *str2;
}

int StringCompareW( PWCHAR str1, PWCHAR str2 ) {
	do {
		if ( *str1 != *str2 ) return FALSE;
	} while ( *( ++str1 ) && *( ++str2 ) );

	if ( ! *str1 ) str2++;

	return *str1 == *str2;
}

// disable optimisation otherwise it will call strlen and resolving will fail
// yeah weird, thanks @C5pider for figuring this out so quickly
#pragma GCC push_options
#pragma GCC optimize ("O0")

int StringLenA( char *str ) {
	int cnt = 0;

	do {
		cnt++;
	} while ( *( ++str ) );

	return cnt;
}

int StringLenW( wchar_t *str ) {
	int cnt = 0;

	do {
		cnt++;
	} while ( *( ++str ) );

	return cnt;
}

#pragma GCC pop_options


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
		NtCurrentHeap(), HEAP_ZERO_MEMORY, UnicodeString->MaximumLength );
	CharStringToWCharString( UnicodeString->Buffer, String, Length );
}

PWSTR *StringSplitW(
	IN PWSTR    str,
	IN WCHAR    delimitor,
	OUT PUSHORT nbr
) {
	PWSTR *array = { 0 };
	ULONG  sz    = { 0 };
	PWSTR  ptr   = str;

	do {
		if ( *str == delimitor ) {
			//
			// allocate memory
			//
			if ( *nbr == 0 ) {
				array = NTDLL$RtlAllocateHeap( NtCurrentHeap(), HEAP_ZERO_MEMORY, sizeof( PWSTR ) );
			} else {
				array = NTDLL$RtlReAllocateHeap( NtCurrentHeap(), HEAP_ZERO_MEMORY, array,
				                                 ( *nbr + 1 ) * sizeof( PWSTR ) );
			}

			//
			// copy the string for persistence
			//
			sz            = C_PTR( str ) - C_PTR( ptr );
			array[ *nbr ] = NTDLL$RtlAllocateHeap( NtCurrentHeap(), HEAP_ZERO_MEMORY, sz + sizeof( WCHAR ) );
			MemCopy( array[ ( *nbr )++ ], ptr, sz );

			//
			// change the offset
			// points to the first character of the next string
			//
			ptr = str + 1;
		}
	} while ( *( ++str ) );

	return array;
}

VOID StringSplitFreeW(
	IN PWSTR *strings,
	IN USHORT nbr
) {
	for ( int i = 0 ; i < nbr ; i++ ) {
		//
		// free each string
		//
		NTDLL$RtlFreeHeap( NtCurrentHeap(), 0, strings[ i ] );
	}

	NTDLL$RtlFreeHeap( NtCurrentHeap(), 0, strings );
}

VOID ConvertBytesToHexStringW(
	IN PBYTE  buffer,
	IN USHORT sz,
	OUT PWSTR str
) {
	BYTE nbr1 = { 0 };
	BYTE nbr2 = { 0 };

	for ( int i = 0 ; i < sz ; i++ ) {
		nbr1 = buffer[ i ] / 16;
		nbr2 = buffer[ i ] - nbr1 * 16;

		str[ i * 2 ]     = ( nbr1 < 10 ) ? nbr1 + 48 : nbr1 + 55;
		str[ i * 2 + 1 ] = ( nbr2 < 10 ) ? nbr2 + 48 : nbr2 + 55;
	}
}
