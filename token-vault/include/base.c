#include <Defs.h>
#ifndef bufsize
#define bufsize 8192
#endif

// not my code, credits go to 5pider: https://twitter.com/C5pider

/*!
 * @brief
 *  Hashing data
 *
 * @param String
 *  Data/String to hash
 *
 * @param Length
 *  size of data/string to hash.
 *  if 0 then hash data til null terminator is found.
 *
 * @return
 *  hash of specified data/string
 */
ULONG HashString(
		_In_ PVOID  String,
_In_ SIZE_T Length
) {
	ULONG  Hash = { 0 };
	PUCHAR Ptr  = { 0 };
	UCHAR  Char = { 0 };

	if ( ! String ) {
		return 0;
	}

	Hash = H_MAGIC_KEY;
	Ptr  = ( ( PUCHAR ) String );

	do {
		Char = *Ptr;

		if ( ! Length ) {
			if ( ! *Ptr ) break;
		} else {
			if ( U_PTR( Ptr - U_PTR( String ) ) >= Length ) break;
			if ( !*Ptr ) ++Ptr;
		}

		if ( Char >= 'a' ) {
			Char -= 0x20;
		}

		Hash = ( ( Hash << 5 ) + Hash ) + Char;

		++Ptr;
	} while ( TRUE );

	return Hash;
}

/*!
 * @brief
 *  get the address of a module
 *
 * @param Hash
 *  hash of the module to get
 *
 * @return
 *  address of the DLL base ( NULL if not found )
 */
PVOID LdrModulePeb(
	_In_ ULONG Hash
) {
	PLDR_DATA_TABLE_ENTRY Data  = { 0 };
	PLIST_ENTRY           Head  = { 0 };
	PLIST_ENTRY           Entry = { 0 };

	Head  = & NtCurrentPeb()->Ldr->InLoadOrderModuleList;
	Entry = Head->Flink;

	for ( ; Head != Entry ; Entry = Entry->Flink ) {
		Data = C_PTR( Entry );

		if ( HashString( Data->BaseDllName.Buffer, Data->BaseDllName.Length ) == Hash ) {
			return Data->DllBase;
		}
	}

	return NULL;
}

/*!
 * @brief
 *  retrieve image header
 *
 * @param Image
 *  image base pointer to retrieve header from
 *
 * @return
 *  pointer to Nt Header
 */
PIMAGE_NT_HEADERS LdrpImageHeader(
	_In_ PVOID Image
) {
	PIMAGE_DOS_HEADER DosHeader = { 0 };
	PIMAGE_NT_HEADERS NtHeader  = { 0 };

	DosHeader = C_PTR( Image );

	if ( DosHeader->e_magic != IMAGE_DOS_SIGNATURE ) {
		return NULL;
	}

	NtHeader = C_PTR( U_PTR( Image ) + DosHeader->e_lfanew );

	if ( NtHeader->Signature != IMAGE_NT_SIGNATURE ) {
		return NULL;
	}

	return NtHeader;
}

/*!
 * @brief
 *  load the address of a function from base DLL address
 *
 * @param Library
 *  base address of the DLL
 *
 * @param Function
 *  hash of the function to get the address of
 *
 * @return
 *  address of the function ( NULL if not found )
 */
PVOID LdrFunctionAddr(
	_In_ PVOID Library,
	_In_ ULONG Function
) {

	PVOID                   Address    = { 0 };
	PIMAGE_NT_HEADERS       NtHeader   = { 0 };
	PIMAGE_EXPORT_DIRECTORY ExpDir     = { 0 };
	SIZE_T                  ExpDirSize = { 0 };
	PDWORD                  AddrNames  = { 0 };
	PDWORD                  AddrFuncs  = { 0 };
	PWORD                   AddrOrdns  = { 0 };
	PCHAR                   FuncName   = { 0 };

	// sanity check arguments
	if ( ! Library || ! Function ) {
		return NULL;
	}

	// retrieve header of library
	if ( ! ( NtHeader = LdrpImageHeader( Library ) ) ) {
		return NULL;
	}

	// parse the header export address table
	ExpDir     = C_PTR( Library + NtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress );
	ExpDirSize = NtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].Size;
	AddrNames  = C_PTR( Library + ExpDir->AddressOfNames );
	AddrFuncs  = C_PTR( Library + ExpDir->AddressOfFunctions );
	AddrOrdns  = C_PTR( Library + ExpDir->AddressOfNameOrdinals );

	// iterate over export address table director
	for ( DWORD i = 0; i < ExpDir->NumberOfNames; i++ ) {
		// retrieve function name
		FuncName = C_PTR( U_PTR( Library ) + AddrNames[ i ] );

		// hash function name from Iat and
		// check the function name is what we are searching for.
		// if not found keep searching.
		if ( HashString( FuncName, 0 ) != Function ) {
			continue;
		}

		// resolve function pointer
		Address = C_PTR( U_PTR( Library ) + AddrFuncs[ AddrOrdns[ i ] ] );

		// check if function is a forwarded function
		if ( ( U_PTR( Address ) >= U_PTR( ExpDir ) ) && ( U_PTR( Address ) <  U_PTR( ExpDir ) + ExpDirSize ) ) {
			CHAR  ForwarderName[ MAX_PATH ] = { 0 };
			DWORD DotOffset	   = 0;
			PCHAR FunctionMod  = NULL;
			PCHAR FunctionName = NULL;

			// save the forwarder string into our ForwarderName buffer
			memcpy( ForwarderName, Address, MSVCRT$strlen( ( PCHAR ) Address ) );

			// first find the offset of the dot '.'
			for ( INT i = 0; i < MSVCRT$strlen( ( PCHAR ) ForwarderName ); i++ ) {
				// check for the '.'
				if ( ( ( PCHAR ) ForwarderName )[ i ] == '.' ) {
					DotOffset = i;			   // save the dot offset/index
					ForwarderName[ i ] = 0; // replace the dot with a NULL terminator
					break;
				}
			}

			FunctionMod  = ForwarderName;
			FunctionName = ForwarderName + DotOffset + 1;

			return LdrFunctionAddr( KERNEL32$LoadLibraryA( FunctionMod ), HashString( FunctionName, 0 ) );
		}

		break;
	}

	return Address;
}

// not my code from here, credits go to: https://github.com/trustedsec/CS-Situational-Awareness-BOF

char * output __attribute__((section (".data"))) = 0;  // this is just done so its we don't go into .bss which isn't handled properly
WORD currentoutsize __attribute__((section (".data"))) = 0;

int bofstart();
void internal_printf(const char* format, ...);
void printoutput(BOOL done);
char * Utf16ToUtf8(const wchar_t* input);
int bofstart()
{   
    output = (char*)MSVCRT$calloc(bufsize, 1);
    currentoutsize = 0;
    return 1;
}

void internal_printf(const char* format, ...){
    int buffersize = 0;
    int transfersize = 0;
    char * curloc = NULL;
    char* intBuffer = NULL;
    va_list args;
    va_start(args, format);
    buffersize = MSVCRT$vsnprintf(NULL, 0, format, args); // +1 because vsprintf goes to buffersize-1 , and buffersize won't return with the null
    va_end(args);
    
    // vsnprintf will return -1 on encoding failure (ex. non latin characters in Wide string)
    if (buffersize == -1)
        return;
    
    char* transferBuffer = (char*)intAlloc(bufsize);
    intBuffer = (char*)intAlloc(buffersize);
    /*Print string to memory buffer*/
    va_start(args, format);
    MSVCRT$vsnprintf(intBuffer, buffersize, format, args); // tmpBuffer2 has a null terminated string
    va_end(args);
    if(buffersize + currentoutsize < bufsize) // If this print doesn't overflow our output buffer, just buffer it to the end
    {
        //BeaconFormatPrintf(&output, intBuffer);
        memcpy(output+currentoutsize, intBuffer, buffersize);
        currentoutsize += buffersize;
    }
    else // If this print does overflow our output buffer, lets print what we have and clear any thing else as it is likely this is a large print
    {
        curloc = intBuffer;
        while(buffersize > 0)
        {
            transfersize = bufsize - currentoutsize; // what is the max we could transfer this request
            if(buffersize < transfersize) //if I have less then that, lets just transfer what's left
            {
                transfersize = buffersize;
            }
            memcpy(output+currentoutsize, curloc, transfersize); // copy data into our transfer buffer
            currentoutsize += transfersize;
            //BeaconFormatPrintf(&output, transferBuffer); // copy it to cobalt strikes output buffer
            if(currentoutsize == bufsize)
            {
            printoutput(FALSE); // sets currentoutsize to 0 and prints
            }
            memset(transferBuffer, 0, transfersize); // reset our transfer buffer
            curloc += transfersize; // increment by how much data we just wrote
            buffersize -= transfersize; // subtract how much we just wrote from how much we are writing overall
        }
    }
    intFree(intBuffer);
    intFree(transferBuffer);
}

void printoutput(BOOL done)
{
    char * msg = NULL;
    BeaconOutput(CALLBACK_OUTPUT, output, currentoutsize);
    currentoutsize = 0;
    memset(output, 0, bufsize);
    if(done) {MSVCRT$free(output); output=NULL;}
}


char* Utf16ToUtf8(const wchar_t* input)
{
    int ret = Kernel32$WideCharToMultiByte(
        CP_UTF8,
        0,
        input,
        -1,
        NULL,
        0,
        NULL,
        NULL
    );

    char* newString = (char*)intAlloc(sizeof(char) * ret);

    ret = Kernel32$WideCharToMultiByte(
        CP_UTF8,
        0,
        input,
        -1,
        newString,
        sizeof(char) * ret,
        NULL,
        NULL
    );

    if (0 == ret)
    {
        goto fail;
    }

retloc:
    return newString;
/*location to free everything centrally*/
fail:
    if (newString){
        intFree(newString);
        newString = NULL;
    };
    goto retloc;
}