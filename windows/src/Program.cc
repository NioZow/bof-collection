#include <Imperium.h>

namespace Windows {
    FUNC VOID list() {
        HWND                        Window     = Imperium::win32::call< fnGetTopWindow >( H_FUNC( "user32!GetTopWindow" ), NULL );
        PWSTR                       WindowName = { 0 };
        ULONG                       Length     = { 0 };
        ULONG                       ProcId     = { 0 };
        PVOID                       Procs      = { 0 };
        PSYSTEM_PROCESS_INFORMATION ProcInfo   = { 0 };
        ULONG                       Size       = { 0 };
        NTSTATUS                    NtStatus   = { 0 };
        BOOL                        Found      = { 0 };

        //
        // get all process and some intel about them without getting a handle onto those
        //
        Imperium::syscall::indirect< fnNtQuerySystemInformation >(
            H_FUNC( "ntdll!NtQuerySystemInformation" ),
            SystemProcessInformation, nullptr, 0, &Size
        );

        Procs = Imperium::mem::alloc( Size );

        if ( ! NT_SUCCESS( NtStatus = Imperium::syscall::indirect< fnNtQuerySystemInformation >(
            H_FUNC("ntdll!NtQuerySystemInformation"),
            SystemProcessInformation, Procs, Size, &Size
        ) ) ) {
            PRINT_NT_ERROR( "NtQuerySystemInformation", NtStatus );
            return;
        }

        do {
            //
            // skip if the window is not visible
            //
            if ( ! Imperium::win32::call< fnIsWindowVisible >( H_FUNC( "user32!IsWindowVisible" ), Window ) ) {
                continue;
            }

            //
            // get the length of the window name
            //
            Length = ( Imperium::win32::call< fnGetWindowTextLengthW >( H_FUNC( "user32!GetWindowTextLengthW" ), Window ) + 1 ) * sizeof( WCHAR );

            //
            // check there is a window name
            //
            if ( Length > 2 ) {
                //
                // get the window process pid
                //
                Imperium::win32::call< fnGetWindowThreadProcessId >( H_FUNC( "user32!GetWindowThreadProcessId" ), Window, &ProcId );

                //
                // search the process
                //
                ProcInfo = Procs;
                Found    = FALSE;
                do {
                    //
                    // search for the process with that pid
                    //
                    if ( ProcInfo->UniqueProcessId == ProcId ) {
                        //
                        // found it
                        //
                        Found = TRUE;
                        break;
                    }
                } while ( ( ProcInfo->NextEntryOffset ) &&
                          ( ProcInfo = C_PTR( ProcInfo ) + ProcInfo->NextEntryOffset ) );

                //
                // the process was not found, continue
                //
                if ( ! Found ) {
                    continue;
                }

                //
                // get the window name
                //
                WindowName = Imperium::mem::alloc( Length );
                Imperium::win32::call< fnGetWindowTextW >( H_FUNC( "user32!GetWindowTextW" ), Window, WindowName, Length );

                //
                // do not print the default "Program Manager" window
                //
                if ( Imperium::crypto::hash_string( WindowName, Length ) != H_STR( "Program Manager" ) ) {
                    //
                    // print that window information
                    //
                    PRINTF( "=> Found window :\n  => Process : %ls\n  => Window  : %ls\n  => PID     : %ld\n\n",
                            ProcInfo->ImageName.Buffer, WindowName, ProcId );
                }

                //
                // free the memory
                //
                Imperium::mem::free( WindowName );
            }
        } while ( ( Window = Imperium::win32::call< fnGetWindow >( H_FUNC( "user32!GetWindow" ), Window, GW_HWNDNEXT ) ) );

        Imperium::mem::free( ProcInfo );
    }
}

/*!
 * @brief
 *  main function put your code here
 *
 * @param Param
 *  parameters
 */
FUNC VOID Main() {
    IMPERIUM_INSTANCE

    //
    // call LoadLibraryA to have the needed module is our peb
    // wont be able to resolve their functions otherwise
    //
    if ( ! Imperium::win32::call< fnLoadLibraryA >( H_FUNC( "kernel32!LoadLibraryA" ), "user32.dll" ) ) {
        return;
    }

    Windows::list();
}
