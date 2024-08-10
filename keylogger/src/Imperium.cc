#include <Imperium.h>

namespace Imperium {
    namespace win32 {
        /*!
         * @brief
         *  get the address of a function
         *
         * @param SymHash
         *  hashed symbol of the func
         *
         * @param Flags
         *  flags
         *
         * @return
         *  symbol
         */
        FUNC PSYMBOL resolve(
            SYMBOL_HASH SymHash,
            ULONG       Flags
        ) {
            IMPERIUM_INSTANCE

            NTSTATUS NtStatus = { 0 };
            PSYMBOL  Sym      = { 0 };
            PVOID    Module   = { 0 };
            SYSCALL  Func     = { 0 };

            //
            // check if the function had already been resolved before
            //
            if ( ! ( Sym = instance::symbol::get( &SymHash ) ) ||
                 ( ! Sym->Syscall.Ssn && Flags & SymbolSyscall )
            ) {
                //
                // the function has not been resolved before
                //
                if ( Flags & SymbolSyscall ) {
                    //
                    // resolve the syscall
                    //
                    if ( ! NT_SUCCESS( NtStatus = syscall::resolve( SymHash, &Func ) ) ) {
                        return nullptr;
                    }
                } else {
                    //
                    // resolve the library from the peb
                    //
                    if ( ! ( Module = ldr::module( SymHash.Module ) ) ) {
                        //
                        // if it fails call LoadLibraryA (can't for now string hashed)
                        // todo: add support for that instead of loading the library to have it in peb
                        //
                        return nullptr;
                    }

                    //
                    // resolve the func
                    //
                    if ( ! ( Func.Address = ldr::function( Module, SymHash.Function ) ) ) {
                        //
                        // failed to resolve the func
                        //
                        return nullptr;
                    }
                }

                //
                // store the function for later use
                //
                if ( ! ( Sym = instance::symbol::add( SymHash, Func.Address, Func.Ssn ) ) ) {
                    return nullptr;
                }
            }

            //
            // add the syscall to the instance
            //
            if
            ( Flags & SymbolSyscall && Flags & SyscallAddInstance ) {
                Instance()->Syscall = &Sym->Syscall;
            }

            return Sym;
        }
    }

    namespace instance {
        /*!
         * @brief
         *  get a pointer to the instance by reading the peb
         *  this one in located in the process heaps table
         *
         * @return
         *  pointer to the instance
         */
        FUNC PINSTANCE get() {
            PINSTANCE Instance = { 0 };
            ULONG     Context  = { 0 };

            for ( int i = 0 ; i < NtCurrentPeb()->NumberOfHeaps ; i++ ) {
                Context = ( ( PINSTANCE ) ( NtCurrentPeb()->ProcessHeaps[ i ] ) )->Context;

                if ( Context == 0xc0debabe ) {
                    Instance = NtCurrentPeb()->ProcessHeaps[ i ];
                    break;
                }
            }

            return Instance;
        }

        namespace symbol {
            /*!
             * @brief
             *  get a pointer to a function info if it is already stored in memory
             *
             * @return
             *  function address struct
             */
            FUNC PSYMBOL get(
                PSYMBOL_HASH FuncHash
            ) {
                IMPERIUM_INSTANCE

                PSYMBOL FuncAddr = Instance()->Symbol;

                //
                // if there is no function loaded quit now
                //
                if ( ! Instance()->Symbol ) {
                    return NULL;
                }

                //
                // iterate through all loaded functions
                //
                do {
                    //
                    // search if a function has the same hashes and so is the same
                    //
                    if ( FuncAddr->FunctionHash == FuncHash->Function &&
                         FuncAddr->ModuleHash == FuncHash->Module
                    ) {
                        break;
                    }
                } while ( ( FuncAddr = FuncAddr->Next ) );

                return FuncAddr;
            }

            /*!
             * @brief
             *  store the function to load only once
             *
             * @param SymHash
             *  hashes of the func
             *
             * @param SymAddr
             *  addr of the module/function
             *
             * @param Ssn
             *  ssn of the syscall
             */
            FUNC PSYMBOL add(
                SYMBOL_HASH SymHash,
                PVOID       SymAddr,
                USHORT      Ssn = 0
            ) {
                IMPERIUM_INSTANCE

                PSYMBOL *         Sym    = &Instance()->Symbol;
                PVOID             Module = { 0 };
                fnRtlAllocateHeap Func   = { 0 };

                //
                // get the address of the last symbol
                //
                while ( *Sym && ( Sym = &( *Sym )->Next ) );

                //
                // allocate the mem manually
                // cant call mem:alloc cuz it calls win32::call
                // creates a recursive infinite loop
                // todo: find a better way to do this?
                // does not fix anything still does not work
                //
                if ( ! ( Module = ldr::module( H_STR( "ntdll.dll" ) ) ) ) {
                    return nullptr;
                }

                if ( ! ( Func = ldr::function( Module, H_STR( "RtlAllocateHeap" ) ) ) ) {
                    return nullptr;
                }

                *Sym = Func( NtCurrentHeap(), HEAP_ZERO_MEMORY, sizeof( SYMBOL ) );

                //
                // set the symbol
                //
                ( *Sym )->FunctionHash = SymHash.Function;
                ( *Sym )->ModuleHash   = SymHash.Module;
                ( *Sym )->Address      = SymAddr;
                ( *Sym )->Syscall.Ssn  = Ssn;

                return *Sym;
            }
        }
    }

    namespace mem {
        /*!
         * @brief
         *  allocate some memory from the heap
         *  wrapper for ntdll!RtlAllocateHeap
         *
         * @param Size
         *  number of bytes to allocate
         */
        FUNC PVOID alloc(
            ULONG size
        ) {
            return win32::call< fnRtlAllocateHeap >(
                H_FUNC( "ntdll!RtlAllocateHeap" ),
                NtProcessHeap(), HEAP_ZERO_MEMORY, size
            );
        }

        /*!
         * @brief
         *  ptr some memory from the heap
         *  wrapper for ntdll!RtlFreeHeap
         *
         * @param ptr
         *  pointer to memory that needs to be freed
         */
        FUNC VOID free(
            PVOID ptr
        ) {
            win32::call< fnRtlFreeHeap >(
                H_FUNC( "ntdll!RtlFreeHeap" ),
                NtProcessHeap(), 0, ptr
            );
        }

        /*!
         * @brief
         *  reallocate some memory from the heap
         *  wrapper for ntdll!RtlFreeHeap
         *
         * @param ptr
         *  allocated memory buffer
         *
         * @param size
         *  size to allocate
         *
         * @return
         *  pointer to the reallocated memory
         */
        FUNC PVOID realloc(
            PVOID ptr,
            ULONG size
        );
    }

    namespace crypto {
        /*!
         * @brief
         *  hash a string
         *
         * @param String
         *  string to hash
         *
         * @param Length
         *  length of the string
         *
         * @return
         *  hash
         */
        FUNC ULONG hash_string(
            IN PCWSTR String,
            IN ULONG  Length
        ) {
            ULONG  Hash = { 0 };
            USHORT Char = { 0 };
            ULONG  Cnt  = { 0 };

            Hash = RANDOM_KEY;

            if ( ! String ) {
                return 0;
            }

            do {
                Char = *String;

                //
                // turn the character to uppercase
                //
                if ( Char >= 'a' && Char <= 'z' ) {
                    Char -= 0x20;
                }

                Hash = ( ( Hash << SEED ) + Hash ) + Char;
            } while ( ++Cnt < Length && *( ++String ) );

            return Hash;
        }

        /*!
         * @brief
         *  hash a string
         *
         * @param String
         *  string to hash
         *
         * @param Length
         *  length of the string
         *
         * @return
         *  hash
         */
        FUNC ULONG hash_string(
            IN PCSTR String,
            IN ULONG Length
        ) {
            ULONG  Hash = { 0 };
            USHORT Char = { 0 };
            ULONG  Cnt  = { 0 };

            Hash = RANDOM_KEY;

            if ( ! String ) {
                return 0;
            }

            do {
                Char = *String;

                //
                // turn the character to uppercase
                //
                if ( Char >= 'a' && Char <= 'z' ) {
                    Char -= 0x20;
                }

                Hash = ( ( Hash << SEED ) + Hash ) + Char;
            } while ( ++Cnt < Length && *( ++String ) );

            return Hash;
        }
    }

    namespace ldr {
        /*!
         * 5pider implementation, credits go to him
         *
         * @brief
         *  get the address of a module
         *
         * @param ModuleHash
         *  hash of the module to get
         *
         * @return
         *  address of the DLL base ( NULL if not found )
         */
        FUNC PVOID module(
            IN ULONG Hash
        ) {
            PLDR_DATA_TABLE_ENTRY Data  = { 0 };
            PLIST_ENTRY           Head  = { 0 };
            PLIST_ENTRY           Entry = { 0 };

            Head  = &NtCurrentPeb()->Ldr->InLoadOrderModuleList;
            Entry = Head->Flink;

            for ( ; Head != Entry ; Entry = Entry->Flink ) {
                Data = C_PTR( Entry );

                if ( crypto::hash_string( Data->BaseDllName.Buffer, Data->BaseDllName.Length / 2 ) == Hash ) {
                    return Data->DllBase;
                }
            }

            return NULL;
        }

        /*!
         * 5pider implementation, credits go to him
         *
         * @brief
         *  load the address of a function from base DLL address
         *
         * @param Module
         *  base address of the DLL
         *
         * @param FunctionHash
         *  hash of the function to get the address of
         *
         * @return
         *  address of the function ( NULL if not found )
         */
        FUNC PVOID function(
            IN PVOID Library,
            IN ULONG Function
        ) {
            PVOID                   Address    = { 0 };
            PIMAGE_NT_HEADERS       NtHeader   = { 0 };
            PIMAGE_DOS_HEADER       DosHeader  = { 0 };
            PIMAGE_EXPORT_DIRECTORY ExpDir     = { 0 };
            SIZE_T                  ExpDirSize = { 0 };
            PDWORD                  AddrNames  = { 0 };
            PDWORD                  AddrFuncs  = { 0 };
            PWORD                   AddrOrdns  = { 0 };
            PCHAR                   FuncName   = { 0 };

            //
            // sanity check arguments
            //
            if ( ! Library || ! Function ) {
                return NULL;
            }

            //
            // check headers are correct
            //
            DosHeader = C_PTR( Library );
            NtHeader  = C_PTR( U_PTR( Library ) + DosHeader->e_lfanew );

            if ( DosHeader->e_magic != IMAGE_DOS_SIGNATURE ||
                 NtHeader->Signature != IMAGE_NT_SIGNATURE
            ) {
                return NULL;
            }

            //
            // parse the header export address table
            //
            ExpDir     = C_PTR( Library + NtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress );
            ExpDirSize = NtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].Size;
            AddrNames  = C_PTR( Library + ExpDir->AddressOfNames );
            AddrFuncs  = C_PTR( Library + ExpDir->AddressOfFunctions );
            AddrOrdns  = C_PTR( Library + ExpDir->AddressOfNameOrdinals );

            //
            // iterate over export address table director
            //
            for ( DWORD i = 0 ; i < ExpDir->NumberOfNames ; i++ ) {
                //
                // retrieve function name
                //
                FuncName = C_PTR( U_PTR( Library ) + AddrNames[ i ] );

                //
                // hash function name from Iat and
                // check the function name is what we are searching for.
                // if not found keep searching.
                //
                if ( Imperium::crypto::hash_string( FuncName, 0xFFFFFFFF ) != Function ) {
                    continue;
                }

                //
                // resolve function pointer
                //
                Address = C_PTR( U_PTR( Library ) + AddrFuncs[ AddrOrdns[ i ] ] );

                //
                // check if function is a forwarded function
                //
                if ( ( U_PTR( Address ) >= U_PTR( ExpDir ) ) &&
                     ( U_PTR( Address ) < U_PTR( ExpDir ) + ExpDirSize )
                ) {
                    //
                    // todo: add support for forwarded functions
                    //
                    __debugbreak();
                }

                break;
            }

            return Address;
        }
    }

    namespace io {
        /*!
         * took from havoc, credits go to 5pider
         *
         * @brief
         *  custom printf implementation
         *
         * @param fmt
         *  format of the string
         *
         * @param ...
         *  printf parameters
         */
        FUNC VOID printf(
            IN PCSTR fmt,
            ...
        ) {
            IMPERIUM_INSTANCE

            INT     OutputSize   = { 0 };
            PCHAR   OutputString = { 0 };
            va_list VaListArg    = { 0 };

            //
            // sanity check
            //
            if ( ! fmt ) {
                return;
            }

            //
            // get the handle to the output console
            //
            if ( ! Instance()->ConsoleOutput ) {
                win32::call< fnAttachConsole >( H_FUNC( "kernel32!AttachConsole" ), ATTACH_PARENT_PROCESS );

                if ( ! ( Instance()->ConsoleOutput = win32::call< fnGetStdHandle >( H_FUNC( "kernel32!GetStdHandle" ), STD_OUTPUT_HANDLE ) ) ) {
                    return;
                }
            }

            va_start( VaListArg, fmt );

            //
            // allocate space for the final string
            //
            OutputSize   = win32::call< fnVsnprintf >( H_FUNC( "msvcrt!vsnprintf" ), NULL, 0, fmt, VaListArg ) + 1;
            OutputString = mem::alloc( OutputSize );

            //
            // write the final string
            //
            win32::call< fnVsnprintf >( H_FUNC( "msvcrt!vsnprintf" ), OutputString, OutputSize, fmt, VaListArg );

            //
            // write it to the console
            //
            win32::call< fnWriteConsoleA >( H_FUNC( "kernel32!WriteConsoleA" ), Instance()->ConsoleOutput, OutputString, OutputSize, NULL, NULL );

            //
            // free the string
            //
            mem::zero( OutputString, OutputSize );
            mem::free( OutputString );

            va_end( VaListArg );
        }
    }

    namespace syscall {
        /*!
         * @brief
         *  resolve syscall information (SSN, address...)
         *
         * @param SyscallHash
         *  hash of the syscall
         *
         * @param Syscall
         *  struct that will receive the address and ssn of the syscall
         *
         * @return
         *  pointer to a data structure containing information about the syscall
         */
        FUNC NTSTATUS resolve(
            IN SYMBOL_HASH SyscallHash,
            OUT PSYSCALL   Syscall
        ) {
            PBYTE SyscallAddr      = { 0 };
            PBYTE FirstSyscallAddr = { 0 };
            PVOID Ntdll            = { 0 };

            //
            // sanity check
            //
            if ( ! Syscall || ! SyscallHash.Function || ! SyscallHash.Module ) {
                return STATUS_INVALID_PARAMETER;
            }

            //
            // check ntdll address
            //
            if ( ! ( Ntdll = Imperium::ldr::module( SyscallHash.Module ) ) ) {
                return STATUS_INTERNAL_ERROR;
            }

            //
            // get the address of the first syscall and the one we want to resolve
            //
            if ( ! ( SyscallAddr      = Imperium::ldr::function( Ntdll, SyscallHash.Function ) ) ||
                 ! ( FirstSyscallAddr = Imperium::ldr::function( Ntdll, H_STR( "NtAccessCheck" ) ) )
            ) {
                return STATUS_INTERNAL_ERROR;
            }

            //
            // make sure we got the address of the first syscall
            // in case NtAccessCheck is no longer the first syscall
            // might break because of NtQuerySystemTime
            // look for the syscall & ret instruction
            // as long as we find some it means we aren't at the first syscall
            //
            while ( *( FirstSyscallAddr - 0x0E ) == 0x0F &&
                    *( FirstSyscallAddr - 0x0D ) == 0x05 &&
                    *( FirstSyscallAddr - 0x0C ) == 0xC3
            ) {
                FirstSyscallAddr -= 32;
            }

            //
            // calculate the SSN
            // and add the address
            //
            Syscall->Address = SyscallAddr;
            Syscall->Ssn     = ( SyscallAddr - FirstSyscallAddr ) / 32;

            //
            // handle the case of ntdll!NtQuerySystemTime
            // it use to be a system call but no longer is
            // so its syscall stub is just a jmp instruction and is not 32 bytes
            // kinda of mess all offset from there
            //
            if ( ( SyscallAddr - FirstSyscallAddr ) % 32 != 0 ) {
                Syscall->Ssn++;
            }

            return STATUS_SUCCESS;
        }
    }
}
